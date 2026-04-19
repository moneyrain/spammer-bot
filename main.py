"""
Anti-Spam Discord Bot
Dependencies: pip install discord.py python-dotenv
"""

import os
import re
import json
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from pathlib import Path

import discord
from discord.ext import commands
from dotenv import load_dotenv

load_dotenv()


def parse_guild_int_map(raw_value: str) -> dict:
    mapping = {}
    if not raw_value:
        return mapping

    for item in re.split(r"[;,]", raw_value):
        pair = item.strip()
        if not pair or ":" not in pair:
            continue

        guild_id_str, value_str = pair.split(":", 1)
        guild_id_str = guild_id_str.strip()
        value_str = value_str.strip()
        if not guild_id_str or not value_str:
            continue

        try:
            mapping[int(guild_id_str)] = int(value_str)
        except ValueError:
            print(f"[WARNING] Invalid entry ignored in guild map: {pair}")

    return mapping

# ============================================================
# CONFIG
# ============================================================
CONFIG = {
    "token": os.getenv("DISCORD_TOKEN", ""),
    "log_channel_id": int(os.getenv("LOG_CHANNEL_ID", 0) or 0),
    "log_channel_ids": parse_guild_int_map(os.getenv("LOG_CHANNEL_IDS", "")),
    "shame_channel_ids": parse_guild_int_map(os.getenv("SHAME_CHANNEL_IDS", "")),

    # Exempt role IDs. Developer Mode > right-click role > Copy ID
    "exempt_role_ids": [
        int(i) for i in os.getenv("EXEMPT_ROLE_IDS", "").split(",") if i.strip()
    ],

    # Flood: X messages in Y seconds
    "flood_limit": 5,
    "flood_window_sec": 8,

    # Fixed punishment: timeout
    "punishment": "timeout",
    # 3 days = 4320 minutes
    "timeout_minutes": 4320,

    # Minimum score to consider spam (0-100)
    "score_threshold": 60,
}

# ============================================================
# SPAM DETECTION PATTERNS
# ============================================================
SPAM_PATTERNS = [
    {
        "name": "External Discord Invite",
        "regex": re.compile(r"discord\.(gg|com/invite)/[a-zA-Z0-9]+", re.I),
        "score": 80,
    },
    {
        "name": "Crypto / NFT / Airdrop Bait",
        "regex": re.compile(
            r"\b(airdrop|nft|free\s*crypto|pump|giveaway.*token|mint\s*now|claim.*token|presale)\b", re.I
        ),
        "score": 70,
    },
    {
        "name": '"Elon Musk" Scam',
        "regex": re.compile(
            r"\b(elon\s*musk|elon)\b.{0,60}\b(crypto|bitcoin|btc|eth|token|double|investment)\b", re.I
        ),
        "score": 90,
    },
    {
        "name": "NSFW / Cam Spam",
        "regex": re.compile(
            r"\b(cam\s*girl|camgirl|nsfw|onlyfans|only\s*fans|join.*cam|cam.*discord)\b", re.I
        ),
        "score": 95,
    },
    {
        "name": "Sketchy Shortened Link",
        "regex": re.compile(
            r"\b(bit\.ly|tinyurl\.com|t\.co|rb\.gy|cutt\.ly|short\.gg)\b.{0,40}\b(free|earn|join|click)\b",
            re.I,
        ),
        "score": 75,
    },
    {
        "name": "Get-Rich-Quick Promise",
        "regex": re.compile(r"\b(earn|ganhe|ganhar|lucre)\b.{0,30}(\$|USD|BRL|reais)", re.I),
        "score": 65,
    },
]

MEDIA_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4", ".mov", ".avi"}
TIMEOUT_COUNTERS_PATH = Path("timeout_counters.json")


# ============================================================
# FLOOD CONTROL + CROSS-CHANNEL TRACKING
# ============================================================
# { (guild_id, user_id): {"messages": [(channel_id, content, timestamp), ...]} }
flood_tracker: dict = defaultdict(lambda: {"messages": []})
timeout_counters: dict = {}


def load_timeout_counters() -> dict:
    if not TIMEOUT_COUNTERS_PATH.exists():
        return {}

    try:
        with TIMEOUT_COUNTERS_PATH.open("r", encoding="utf-8") as fp:
            data = json.load(fp)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[WARNING] Failed to load {TIMEOUT_COUNTERS_PATH}: {exc}")

    return {}


def save_timeout_counters() -> None:
    try:
        with TIMEOUT_COUNTERS_PATH.open("w", encoding="utf-8") as fp:
            json.dump(timeout_counters, fp, ensure_ascii=False, indent=2)
    except OSError as exc:
        print(f"[ERROR] Failed to save {TIMEOUT_COUNTERS_PATH}: {exc}")


def increment_timeout_count(guild_id: int, user_id: int) -> int:
    key = f"{guild_id}:{user_id}"
    current = int(timeout_counters.get(key, 0)) + 1
    timeout_counters[key] = current
    save_timeout_counters()
    return current


def format_infection_count(count: int) -> str:
    if count == 1:
        return "1st"
    if count == 2:
        return "2nd"
    if count == 3:
        return "3rd"
    if count == 4:
        return "4th"
    if count == 5:
        return "5th"
    return f"{count}th"


def get_log_channel_id(guild_id: int) -> int:
    return CONFIG["log_channel_ids"].get(guild_id, CONFIG["log_channel_id"])


def get_shame_channel_id(guild_id: int) -> int:
    return CONFIG["shame_channel_ids"].get(guild_id, 0)


def check_flood(guild_id: int, user_id: int, channel_id: int, content: str) -> tuple:
    now = datetime.now(timezone.utc)
    window = timedelta(seconds=CONFIG["flood_window_sec"])
    data = flood_tracker[(guild_id, user_id)]

    # Remove entries outside the time window
    data["messages"] = [
        (ch, c, t) for ch, c, t in data["messages"]
        if now - t < window
    ]
    data["messages"].append((channel_id, content, now))
    msgs = data["messages"]

    # Flood in the same channel
    same_channel = [m for m in msgs if m[0] == channel_id]
    duplicates = sum(1 for _, c, _ in same_channel if c == content)

    if duplicates >= 3:
        return True, f"sent the same message {duplicates}x like a broken robot"
    if len(same_channel) >= CONFIG["flood_limit"]:
        return True, f"{len(same_channel)} messages in the same channel within {CONFIG['flood_window_sec']}s"

    # Cross-channel: same content spread across different channels
    channels_used = {ch for ch, _, _ in msgs}
    if len(channels_used) >= 2:
        unique_contents = {c for _, c, _ in msgs}
        if len(unique_contents) <= 2:
            return True, f"spammed the same trash in {len(channels_used)} different channels bro what"

    # Cross-channel: high volume across 3+ channels in a short time
    if len(channels_used) >= 3 and len(msgs) >= 4:
        return True, f"threw {len(msgs)} messages in {len(channels_used)} channels like a maniac ({CONFIG['flood_window_sec']}s)"

    return False, ""


# ============================================================
# SPAM ANALYSIS
# ============================================================
def analyze_message(message: discord.Message) -> tuple:
    total_score = 0
    reasons = []
    content = message.content

    # Text patterns
    for pattern in SPAM_PATTERNS:
        if pattern["regex"].search(content):
            total_score += pattern["score"]
            reasons.append(pattern["name"])

    # @everyone / @here → instant max score
    if message.mention_everyone:
        total_score += 100
        reasons.append("@everyone or @here mention")

    # 3+ users mentioned
    unique_mentions = {m.id for m in message.mentions}
    if len(unique_mentions) >= 3:
        total_score += 70
        reasons.append(f"pinged {len(unique_mentions)} people who all hate them now")

    # 2+ media files → immediate alert
    media_attachments = [
        a for a in message.attachments
        if any(a.filename.lower().endswith(ext) for ext in MEDIA_EXTENSIONS)
    ]
    if len(media_attachments) >= 2:
        total_score += 80
        reasons.append(f"dumped {len(media_attachments)} files like nobody asked (they didnt)")

    # Bonus for suspicious combos
    has_mention = message.mention_everyone or len(unique_mentions) >= 3
    has_discord_link = bool(re.search(r"discord\.(gg|com/invite)/[a-zA-Z0-9]+", content, re.I))

    if has_mention and has_discord_link:
        total_score += 30
        reasons.append("Combo: mass ping + Discord invite")

    if has_mention and len(media_attachments) >= 2:
        total_score += 30
        reasons.append("Combo: mass ping + media dump")

    if len(media_attachments) >= 2 and has_discord_link:
        total_score += 30
        reasons.append("Combo: media dump + Discord invite")

    return min(total_score, 100), reasons


# ============================================================
# BOT
# ============================================================
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix="!", intents=intents)


def get_punish_block_reason(member: discord.Member, punishment: str) -> str:
    me = member.guild.me
    if me is None:
        return "Bot not found in guild cache (guild.me=None)."

    permissions_needed = {
        "timeout": ["moderate_members"],
    }
    needed = permissions_needed.get(punishment, [])
    missing = [perm for perm in needed if not getattr(me.guild_permissions, perm, False)]
    if missing:
        return f"Missing permissions for {punishment}: {', '.join(missing)}"

    if member == member.guild.owner:
        return "cant punish the owner. trust me i tried"

    # Discord hierarchy rule: bot's top role must be above the target's.
    if me.top_role <= member.top_role:
        return (
            "Invalid role hierarchy "
            f"(bot role: {me.top_role.name} <= target role: {member.top_role.name})."
        )

    return ""


async def punish(member: discord.Member, reason: str) -> bool:
    punishment = "timeout"

    block_reason = get_punish_block_reason(member, punishment)
    if block_reason:
        print(
            "[WARNING] Punishment blocked | "
            f"guild={member.guild.name} ({member.guild.id}) | "
            f"target={member} ({member.id}) | reason={block_reason}"
        )
        return False

    try:
        until = datetime.now(timezone.utc) + timedelta(minutes=CONFIG["timeout_minutes"])
        await member.timeout(until, reason=reason)
        return True
    except discord.Forbidden as exc:
        print(
            "[WARNING] Discord blocked the punishment | "
            f"guild={member.guild.name} ({member.guild.id}) | "
            f"target={member} ({member.id}) | type={punishment} | error={exc}"
        )
        return False
    except discord.HTTPException as exc:
        print(
            "[ERROR] HTTP failure while punishing user | "
            f"guild={member.guild.name} ({member.guild.id}) | "
            f"target={member} ({member.id}) | type={punishment} | error={exc}"
        )
        return False


async def log_action(guild: discord.Guild, message: discord.Message, reasons: list, score: int):
    log_channel_id = get_log_channel_id(guild.id)
    if not log_channel_id:
        return

    channel = guild.get_channel(log_channel_id)
    if not channel:
        try:
            channel = await guild.fetch_channel(log_channel_id)
        except (discord.NotFound, discord.Forbidden, discord.HTTPException) as exc:
            print(
                f"[WARNING] Could not access log channel {log_channel_id} "
                f"in guild {guild.name} ({guild.id}) | error={exc}"
            )
            return

    if not channel:
        print(f"[WARNING] Log channel {log_channel_id} not found in guild {guild.name} ({guild.id})")
        return

    embed = discord.Embed(
        title="🚫 Spam Nuked",
        color=discord.Color.red(),
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(name="User", value=f"{message.author} (`{message.author.id}`)", inline=False)
    embed.add_field(name="Channel", value=message.channel.mention, inline=True)
    embed.add_field(name="Score", value=f"{score}/100", inline=True)
    embed.add_field(name="Reasons", value="\n".join(f"• {r}" for r in reasons), inline=False)

    if message.content:
        preview = message.content[:300] + ("..." if len(message.content) > 300 else "")
        embed.add_field(name="Content", value=f"```{preview}```", inline=False)

    if message.attachments:
        attach_list = "\n".join(f"• {a.filename}" for a in message.attachments[:10])
        embed.add_field(name="Attachments", value=attach_list, inline=False)

    embed.set_footer(text=f"Punishment: {CONFIG['punishment']}")
    try:
        await channel.send(embed=embed)
    except discord.Forbidden as exc:
        print(
            f"[WARNING] No permission to send log in channel {log_channel_id} "
            f"in guild {guild.name} ({guild.id}) | error={exc}"
        )
    except discord.HTTPException as exc:
        print(
            f"[ERROR] HTTP failure sending log in channel {log_channel_id} "
            f"in guild {guild.name} ({guild.id}) | error={exc}"
        )


async def send_shame_wall(guild: discord.Guild, member: discord.Member, timeout_count: int):
    shame_channel_id = get_shame_channel_id(guild.id)
    if not shame_channel_id:
        print(f"[WARNING] Hall of Shame channel not configured for guild {guild.name} ({guild.id})")
        return

    channel = guild.get_channel(shame_channel_id)
    if not channel:
        try:
            channel = await guild.fetch_channel(shame_channel_id)
        except (discord.NotFound, discord.Forbidden, discord.HTTPException) as exc:
            print(
                f"[WARNING] Could not access Hall of Shame channel {shame_channel_id} "
                f"in guild {guild.name} ({guild.id}) | error={exc}"
            )
            return

    if not channel:
        print(f"[WARNING] Hall of Shame channel {shame_channel_id} not found in guild {guild.name} ({guild.id})")
        return

    occurrence = format_infection_count(timeout_count)
    if timeout_count >= 2:
        embed = discord.Embed(
            title="☠️ Hall of Shame ☠️",
            description=(
                f"{member.mention} got timed out for the **{occurrence}** time 💀\n\n"
                "bro came back and did it AGAIN\n"
                "at this point we think ur just lonely\n"
                "its ok we still dont want u here"
            ),
            color=0x8B0000,
        )
    else:
        embed = discord.Embed(
            title="☠️ Hall of Shame ☠️",
            description=(
                f"{member.mention} got timed out for the **{occurrence}** time lmao\n\n"
                "bro clicked a random link like a golden retriever seeing a ball\n"
                "turn on windows defender and never touch a keyboard again"
            ),
            color=0x8B0000,
        )
    embed.set_thumbnail(url=member.display_avatar.url)
    embed.set_footer(text=f"timeout #{timeout_count} | aim club does not miss")
    try:
        await channel.send(embed=embed)
    except discord.Forbidden as exc:
        print(
            f"[WARNING] No permission to send Hall of Shame in channel {shame_channel_id} "
            f"in guild {guild.name} ({guild.id}) | error={exc}"
        )
    except discord.HTTPException as exc:
        print(
            f"[ERROR] HTTP failure sending Hall of Shame in channel {shame_channel_id} "
            f"in guild {guild.name} ({guild.id}) | error={exc}"
        )


def is_exempt(member: discord.Member) -> bool:
    if member.guild_permissions.administrator:
        return True
    member_role_ids = {r.id for r in member.roles}
    return bool(member_role_ids & set(CONFIG["exempt_role_ids"]))


@bot.event
async def on_ready():
    global timeout_counters
    timeout_counters = load_timeout_counters()

    print(f"✅ Bot connected as {bot.user} ({bot.user.id})")
    print(f"   Punishment: {CONFIG['punishment']} | Threshold: {CONFIG['score_threshold']}")
    if CONFIG["log_channel_ids"]:
        print(f"   Log channels by guild: {len(CONFIG['log_channel_ids'])} configured")
    elif CONFIG["log_channel_id"]:
        print(f"   Default log channel: {CONFIG['log_channel_id']}")
    if CONFIG["shame_channel_ids"]:
        print(f"   Hall of Shame channels by guild: {len(CONFIG['shame_channel_ids'])} configured")

    for guild in bot.guilds:
        log_channel_id = get_log_channel_id(guild.id)
        shame_channel_id = get_shame_channel_id(guild.id)
        print(
            f"   Guild: {guild.name} ({guild.id}) | "
            f"Log: {log_channel_id or 'not configured'} | "
            f"Shame: {shame_channel_id or 'not configured'}"
        )
    print(f"   Timeout counters loaded: {len(timeout_counters)} record(s)")


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return

    if is_exempt(message.author):
        await bot.process_commands(message)
        return

    # 1. Flood + cross-channel
    is_flood, flood_reason = check_flood(
        message.guild.id, message.author.id, message.channel.id, message.content
    )

    # 2. Content + attachments + mentions
    score, reasons = analyze_message(message)

    spam_detected = is_flood or score >= CONFIG["score_threshold"]

    if spam_detected:
        if is_flood:
            reasons.insert(0, f"Flood: {flood_reason}")
            score = max(score, 85)

        try:
            await message.delete()
        except (discord.NotFound, discord.Forbidden):
            pass

        try:
            warn_embed = discord.Embed(
                title="💀 Bro got caught lackin",
                description=(
                    f"{message.author.mention} ur message got deleted bro\n\n"
                    "we also reported u to ur mom\n"
                    "she said shes disappointed (again)"
                ),
                color=0xFF0000,
            )
            warn_embed.set_footer(text="this message will self destruct in 8s")
            await message.channel.send(embed=warn_embed, delete_after=8)
        except discord.Forbidden:
            pass

        timeout_applied = await punish(message.author, reason=f"Spam: {', '.join(reasons)}")
        await log_action(message.guild, message, reasons, score)
        if timeout_applied:
            timeout_count = increment_timeout_count(message.guild.id, message.author.id)
            await send_shame_wall(message.guild, message.author, timeout_count)
        print(f"[SPAM] {message.author} | Score: {score} | {reasons}")
        return

    await bot.process_commands(message)


# ============================================================
# TEST COMMAND (admins only)
# ============================================================
@bot.command(name="testspam")
@commands.has_permissions(administrator=True)
async def test_spam(ctx, *, texto: str):
    """Tests whether a text would be detected as spam. Usage: !testspam <text>"""
    total_score = 0
    reasons = []
    for pattern in SPAM_PATTERNS:
        if pattern["regex"].search(texto):
            total_score += pattern["score"]
            reasons.append(pattern["name"])
    score = min(total_score, 100)
    is_spam = score >= CONFIG["score_threshold"]

    embed = discord.Embed(
        title="🔍 Spam Analysis Result",
        color=discord.Color.red() if is_spam else discord.Color.green(),
    )
    embed.add_field(name="Score", value=f"{score}/100", inline=True)
    embed.add_field(name="Is Spam?", value="yeah delete that thing 💀" if is_spam else "its fine let it cook ✅", inline=True)
    embed.add_field(
        name="Note",
        value="Attachments, mentions, and cross-channel behavior are only analyzed on real messages.",
        inline=False,
    )
    if reasons:
        embed.add_field(name="Patterns Matched", value="\n".join(f"• {r}" for r in reasons), inline=False)
    await ctx.reply(embed=embed)


# ============================================================
# START
# ============================================================
if __name__ == "__main__":
    token = CONFIG["token"]
    if not token:
        raise ValueError("Set DISCORD_TOKEN in your .env file")
    bot.run(token)