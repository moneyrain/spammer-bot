"""
Anti-Spam Discord Bot
Dependencies: pip install discord.py python-dotenv
"""

import os
import re
import json
import random
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
    # raised to 75 so single weak pattern hits don't mute people
    "score_threshold": 75,

    # Ticket/support channel IDs where media is allowed freely
    # Add channel IDs here: [123456789, 987654321]
    "ticket_channel_ids": [
        int(i) for i in os.getenv("TICKET_CHANNEL_IDS", "").split(",") if i.strip()
    ],
}

# ============================================================
# SPAM DETECTION PATTERNS
# ============================================================
SPAM_PATTERNS = [
    # ── discord invite ─────────────────────────────────────────
    # raw invite links are always actionable, no intent needed
    {
        "name": "External Discord Invite",
        "regex": re.compile(r"discord\.(gg|com/invite)/[a-zA-Z0-9]+", re.I),
        "score": 80,
    },

    # ── crypto / nft ───────────────────────────────────────────
    # "nft" / "crypto" alone too common in gaming chat, require action word
    {
        "name": "Crypto / NFT / Airdrop Bait",
        "regex": re.compile(
            r"\b(airdrop|free\s*crypto|giveaway.*token|mint\s*now|claim.*token|presale"
            r"|nft.{0,40}(buy|sell|mint|claim|free|drop|join|link|dm))\b",
            re.I,
        ),
        "score": 80,
    },
    # elon + crypto combo is always a scam regardless
    {
        "name": '"Elon Musk" Scam',
        "regex": re.compile(
            r"\b(elon\s*musk|elon)\b.{0,60}\b(crypto|bitcoin|btc|eth|token|double|investment)\b", re.I
        ),
        "score": 100,
    },

    # ── nsfw / cam ─────────────────────────────────────────────
    # always spam in any context
    {
        "name": "NSFW / Cam Spam",
        "regex": re.compile(
            r"\b(cam\s*girl|camgirl|onlyfans|only\s*fans|join.*cam|cam.*discord)\b", re.I
        ),
        "score": 100,
    },

    # ── shortened links ────────────────────────────────────────
    # already requires action word, keep as is
    {
        "name": "Sketchy Shortened Link",
        "regex": re.compile(
            r"\b(bit\.ly|tinyurl\.com|t\.co|rb\.gy|cutt\.ly|short\.gg)\b.{0,40}\b(free|earn|join|click)\b",
            re.I,
        ),
        "score": 85,
    },

    # ── money promises ─────────────────────────────────────────
    # require $ + number so "earn xp" or "earn coins" dont trigger
    {
        "name": "Get-Rich-Quick Promise",
        "regex": re.compile(r"\b(earn|make)\b.{0,30}(\$\d+|USD|BRL)", re.I),
        "score": 75,
    },

    # ── free nitro ─────────────────────────────────────────────
    # "nitro" alone fine, require "free" or "claim" combo
    {
        "name": "Fake Free Nitro",
        "regex": re.compile(
            r"\b(free\s*nitro|nitro\s*giveaway|claim.*nitro|nitro.*claim"
            r"|discord\s*nitro.{0,30}(free|click|link|dm|get))\b",
            re.I,
        ),
        "score": 90,
    },
    # raw gift links are always spam
    {
        "name": "Fake discord.gift Link",
        "regex": re.compile(r"discord\.gift/[a-zA-Z0-9]+", re.I),
        "score": 85,
    },

    # ── phishing ───────────────────────────────────────────────
    # require full suspicious phrase, not just "verify"
    {
        "name": "Fake Login / Phishing",
        "regex": re.compile(
            r"\b(login\s*to\s*claim|your\s*account\s*will\s*be\s*(banned|deleted|terminated)"
            r"|verify\s*your\s*account.{0,30}(link|click|here|now)"
            r"|confirm\s*your\s*identity.{0,30}(link|click))\b",
            re.I,
        ),
        "score": 85,
    },

    # ── steam phishing ─────────────────────────────────────────
    # "steam" alone fine, require scam combo
    {
        "name": "Steam Account Phishing",
        "regex": re.compile(
            r"\b(link\s*your\s*steam|steam\s*giveaway|free\s*steam\s*game"
            r"|steam.{0,30}(nitro|login\s*here|click\s*here|verify))\b",
            re.I,
        ),
        "score": 85,
    },

    # ── game cheat / malware ───────────────────────────────────
    # aimbot/wallhack alone = normal gaming talk, require download/sell intent
    {
        "name": "Game Cheat / Hack Malware",
        "regex": re.compile(
            r"\b(free\s*hack|free\s*cheat|free\s*mod\s*menu|undetected\s*cheat|free\s*cheats?\s*download"
            r"|(aimbot|wallhack|esp\s*hack).{0,40}(download|link|buy|get\s*it|free|shop|store|dm\s*me|click))\b",
            re.I,
        ),
        "score": 75,
    },

    # ── token grabbers ─────────────────────────────────────────
    # always 100, no legit reason to say these in chat
    {
        "name": "Token Grabber / Account Takeover",
        "regex": re.compile(
            r"\b(token\s*logger|token\s*grabber|steal\s*token|selfbot)\b", re.I
        ),
        "score": 100,
    },

    # ── qr code scams ──────────────────────────────────────────
    # "qr code" alone fine, require scam action combo
    {
        "name": "QR Code Scam",
        "regex": re.compile(
            r"\b(scan\s*(this\s*)?qr.{0,30}(free|nitro|claim|win|reward|login)"
            r"|qr\s*code.{0,30}(free|nitro|claim|win|reward|login))\b",
            re.I,
        ),
        "score": 85,
    },

    # ── fake giveaway wins ─────────────────────────────────────
    # "congratulations" alone fine, require claim/link combo
    {
        "name": "Fake Giveaway Win",
        "regex": re.compile(
            r"\b(you\s*have\s*(won|been\s*selected).{0,40}(claim|link|click|prize)"
            r"|congratulations.{0,40}(claim|click|link|prize|reward)"
            r"|claim\s*your\s*(prize|reward|gift))\b",
            re.I,
        ),
        "score": 85,
    },

    # ── pump and dump ──────────────────────────────────────────
    # "100x" alone = gaming talk, require crypto context
    {
        "name": "Pump and Dump / Investment Scam",
        "regex": re.compile(
            r"\b(pump\s*and\s*dump"
            r"|(100x|1000x).{0,40}(crypto|token|coin|invest)"
            r"|guaranteed\s*(profit|return|gain).{0,40}(crypto|token|invest|coin)"
            r"|invest\s*now.{0,30}(crypto|token|coin)"
            r"|passive\s*income.{0,30}(crypto|invest|token))\b",
            re.I,
        ),
        "score": 85,
    },

    # ── job scams ──────────────────────────────────────────────
    # require earn/$ + action combo, not just "work from home"
    {
        "name": "Fake Job / Work From Home Scam",
        "regex": re.compile(
            r"\b(work\s*from\s*home.{0,30}(earn|\$\d+|easy\s*money)"
            r"|hiring\s*now.{0,30}(no\s*experience|easy\s*money|\$\d+)"
            r"|earn\s*\$\d+\s*per\s*(day|hour|week).{0,30}(dm|click|link|join))\b",
            re.I,
        ),
        "score": 80,
    },

    # ── wallet drainer ─────────────────────────────────────────
    # "wallet" alone fine, require scam combo
    {
        "name": "Crypto Wallet Drainer",
        "regex": re.compile(
            r"\b(connect\s*your\s*wallet.{0,40}(free|claim|reward|airdrop|here|now)"
            r"|wallet\s*connect.{0,30}(free|claim|reward|airdrop)"
            r"|metamask.{0,40}(claim|free|airdrop)"
            r"|seed\s*phrase|wallet\s*drainer)\b",
            re.I,
        ),
        "score": 100,
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
# CASUAL / JOKE CONTEXT DETECTION
# ============================================================
# these patterns suggest someone is joking or talking casually
# if matched, score gets reduced so normal chat doesn't get muted
CASUAL_INDICATORS = re.compile(
    r"\b(lol|lmao|lmfao|haha|hahaha|kkkk|bruh|bro|imagine|fr\s*fr|ngl|tbh|imo|smh|💀|😂|🤣"
    r"|what\s*if|would\s*be\s*(crazy|wild|insane|sick|cool|funny)"
    r"|i\s*wish|wish\s*i|if\s*only|that'?s?\s*(crazy|wild|insane|cap|facts)"
    r"|no\s*way|ain'?t?\s*no\s*way|ratio|based|cope|seethe|skill\s*issue"
    r"|talking\s*about|heard\s*(about|of)|remember\s*when|back\s*when"
    r"|they\s*said|people\s*saying|saw\s*(someone|a\s*guy|this)"
    r"|joking|jk|j\/k|just\s*kidding|sarcasm|not\s*serious)\b",
    re.I,
)

# question marks also suggest discussion, not spam
QUESTION_PATTERN = re.compile(r"\?")


def is_casual_context(content: str) -> bool:
    """returns True if the message looks like casual chat or a joke"""
    return bool(CASUAL_INDICATORS.search(content)) or bool(QUESTION_PATTERN.search(content))


def analyze_message(message: discord.Message) -> tuple:
    total_score = 0
    reasons = []
    content = message.content

    # Text patterns
    for pattern in SPAM_PATTERNS:
        if pattern["regex"].search(content):
            total_score += pattern["score"]
            reasons.append(pattern["name"])

    # if message looks like casual chat / joke, cut the score in half
    # this won't save actual scammers since their scores are 100 or stack high
    # but it protects people just talking normally
    if total_score > 0 and is_casual_context(content):
        total_score = total_score // 2
        reasons.append("⚠️ casual/joke context detected — score halved")

    # @everyone / @here → instant max score
    if message.mention_everyone:
        total_score += 100
        reasons.append("@everyone or @here mention")

    # 3+ users mentioned
    unique_mentions = {m.id for m in message.mentions}
    if len(unique_mentions) >= 3:
        total_score += 70
        reasons.append(f"pinged {len(unique_mentions)} people who all hate them now")

    # 2+ media files → only suspicious if combined with other signals
    media_attachments = [
        a for a in message.attachments
        if any(a.filename.lower().endswith(ext) for ext in MEDIA_EXTENSIONS)
    ]
    # media alone is NOT enough — needs a combo to count
    # (tickets, support channels, etc. send images all the time legitimately)

    # Bonus for suspicious combos
    has_mention = message.mention_everyone or len(unique_mentions) >= 3
    has_discord_link = bool(re.search(r"discord\.(gg|com/invite)/[a-zA-Z0-9]+", content, re.I))
    has_spam_pattern = total_score > 0  # already matched a text pattern above

    if has_mention and has_discord_link:
        total_score += 30
        reasons.append("Combo: mass ping + Discord invite")

    if has_mention and len(media_attachments) >= 2:
        total_score += 30
        reasons.append("Combo: mass ping + media dump")

    if len(media_attachments) >= 2 and has_discord_link:
        total_score += 50
        reasons.append("Combo: media dump + Discord invite")

    # media + a spam text pattern = very sus
    if len(media_attachments) >= 2 and has_spam_pattern:
        total_score += 50
        reasons.append(f"Combo: {len(media_attachments)} files + spam text detected")

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
        jokes = [
            f"bro came back and did it AGAIN\nat this point we think ur just lonely\nits ok we still dont want u here",
            f"some people learn from their mistakes\nu are not some people",
            f"the definition of insanity is doing the same thing and expecting different results\nhi insane person",
            f"we genuinely thought u learned last time\nwe were wrong\nu were worse",
            f"at this point ur basically a regular here in the hall of shame\nwe saved u a seat",
        ]
        embed = discord.Embed(
            title=f"☠️ Hall of Shame — {occurrence} time ☠️",
            description=f"{member.mention} {random.choice(jokes)}",
            color=0x8B0000,
        )
    else:
        jokes = [
            "bro clicked a random link like a golden retriever seeing a ball\nturn on windows defender and never touch a keyboard again",
            "we have timed out many people\nbut u? u did it with confidence\nrespect. still timed out tho",
            "ur first time here but something tells us it wont be ur last\nprove us wrong. please.",
            "bro really said 'yeah this looks legit' and sent it\nu need a longer timeout and a better life coach",
        ]
        embed = discord.Embed(
            title="☠️ Hall of Shame — 1st time ☠️",
            description=f"{member.mention} {random.choice(jokes)}",
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

    in_ticket_channel = (
        message.channel.id in CONFIG["ticket_channel_ids"]
        or message.channel.name.startswith("ticket-")
    )

    # 1. Flood + cross-channel (skip in ticket channels)
    is_flood = False
    flood_reason = ""
    if not in_ticket_channel:
        is_flood, flood_reason = check_flood(
            message.guild.id, message.author.id, message.channel.id, message.content
        )

    # 2. Content + attachments + mentions
    score, reasons = analyze_message(message)

    # never punish anyone in ticket channels
    if in_ticket_channel:
        await bot.process_commands(message)
        return

    spam_detected = is_flood or score >= CONFIG["score_threshold"]

    if spam_detected:
        if is_flood:
            reasons.insert(0, f"Flood: {flood_reason}")
            score = max(score, 85)

        try:
            await message.delete()
        except (discord.NotFound, discord.Forbidden):
            pass

        # Pick joke pool based on what was detected
        reasons_text = " ".join(reasons).lower()

        if "nsfw" in reasons_text or "cam" in reasons_text or "onlyfans" in reasons_text:
            title = "🔞 gooner detected"
            jokes = [
                "bro is so lonely he started advertising for others\nseek help. or a hobby. or both.",
                "ur mom found ur search history and asked us to intervene",
                "bro really said 'let me share this with the homies'\nthe homies did not want it",
                "scientists have confirmed that no amount of therapy can fix whatever this is",
            ]

        elif "wallet" in reasons_text or "metamask" in reasons_text or "seed phrase" in reasons_text:
            title = "💸 wallet drainer detected"
            jokes = [
                "bro tried to drain wallets in THIS server\nhis own wallet is probably empty tho",
                "connecting ur wallet to this guy is like giving ur car keys to a raccoon",
                "seed phrase stealer spotted\nbro couldnt afford crypto so he decided to steal it instead",
                "ur metamask is safe. ur dignity is not.",
            ]

        elif "token grabber" in reasons_text or "token logger" in reasons_text or "selfbot" in reasons_text:
            title = "🪤 token grabber caught"
            jokes = [
                "bro sent a token grabber in a server full of people who know what a token grabber is\nrespect the confidence. zero respect for the iq.",
                "tried to steal accounts and got his own deleted instead\nkarma speedrun any%",
                "token grabber in 2025 bro ur not even original\ngo touch grass and think of something new",
            ]

        elif "nitro" in reasons_text or "discord.gift" in reasons_text:
            title = "🎁 fake nitro scammer"
            jokes = [
                "free nitro lmaooo\nbro the oldest trick in the book and u still tried it",
                "nobody has ever gotten free nitro from a random discord link\nnobody. not once. not ever.",
                "ur nitro scam is older than some of the members in this server\nretire.",
                "discord.gift/goToJail\nthat's where ur headed",
            ]

        elif "steam" in reasons_text or "game cheat" in reasons_text or "hack" in reasons_text or "aimbot" in reasons_text:
            title = "🎮 gaming scammer spotted"
            jokes = [
                "free aimbot bro really said free aimbot\nu gonna get vac banned AND server banned same day",
                "the only thing u hacked today was ur own chance of staying in this server",
                "free steam games moment\nnext time just get a job",
                "ur cheat doesnt even work and neither does ur brain",
            ]

        elif "discord staff" in reasons_text or "discord team" in reasons_text or "fake discord" in reasons_text or "phishing" in reasons_text:
            title = "🎭 impersonator caught"
            jokes = [
                "impersonating discord staff\nbro ur not even verified\nu have a default pfp",
                "discord staff dont dm people out of nowhere\nu just proved u have never used discord before",
                "account suspended lol\nthe only account getting suspended is urs. right now.",
                "fake login page in MY server\nbro thought he was smart\nhe was not smart",
            ]

        elif "pump and dump" in reasons_text or "100x" in reasons_text or "guaranteed" in reasons_text or "investment" in reasons_text:
            title = "📉 investment scammer"
            jokes = [
                "guaranteed profit bro\nthe only guaranteed thing here is ur timeout",
                "100x returns 💀 bro the only thing going 100x is how fast we deleted that",
                "passive income from crypto\nbro ur about to passively leave this server",
                "pump and dump detected\nur portfolio and ur reputation both going to zero",
            ]

        elif "work from home" in reasons_text or "job scam" in reasons_text or "earn" in reasons_text:
            title = "💼 job scammer"
            jokes = [
                "earn $500 a day from home\nbro the only thing u earned today is a timeout",
                "no experience needed\ncorrect. scamming requires zero brain cells and u proved it",
                "hiring now lmao\nwe are also hiring. for people who can read the rules.",
                "make money online they said\ncongrats u made zero dollars and lost ur chat access",
            ]

        elif "qr" in reasons_text or "scan" in reasons_text:
            title = "📷 qr code scammer"
            jokes = [
                "sent a qr code to steal accounts\nbro thinks its 2019",
                "nobody is scanning that\nthis isnt a restaurant menu",
                "qr code scam is wild\nbro couldnt even be bothered to type the phishing link himself",
            ]

        elif "giveaway" in reasons_text or "you won" in reasons_text or "winner" in reasons_text:
            title = "🎰 fake giveaway clown"
            jokes = [
                "u won!! 🎉\nu won a timeout. congratulations.",
                "bro entered zero giveaways and somehow won one\ncrazy how that works",
                "claim ur prize by clicking this link\nthe prize is a ban. do not click.",
                "u have been selected\nto leave this server. effective immediately.",
            ]

        elif "elon" in reasons_text or "crypto" in reasons_text or "nft" in reasons_text or "airdrop" in reasons_text:
            title = "🪙 crypto scammer"
            jokes = [
                "bro really thought he was gonna get rich in a discord server\nthat is genuinely heartbreaking",
                "the crypto market crashed and so did ur reputation",
                "elon musk called. he said he doesnt know u and ur embarrassing him",
                "bro bought the dip and the dip bought him a timeout",
                "nft seller spotted. everyone point and laugh",
            ]

        elif "flood" in reasons_text or "same message" in reasons_text or "spamming" in reasons_text:
            title = "🌊 bro spamming like crazy"
            jokes = [
                "sending the same message 10 times doesnt make it more true bro\nit makes u more insane",
                "ur keyboard is fine, we checked. the problem is u",
                "copy paste champion. absolutely nobody asked",
                "bro said it once and thought 'yeah they need to hear this 9 more times'",
            ]

        elif "invite" in reasons_text:
            title = "🔗 server advertiser spotted"
            jokes = [
                "nobody is joining ur server bro\nnot even ur other account",
                "advertising here is crazy work\nespecially since ur server has 3 members including ur mom",
                "bro really thought this was the place\nit was not the place",
            ]

        elif "mention" in reasons_text or "ping" in reasons_text:
            title = "📣 ping abuser"
            jokes = [
                "bro pinged half the server like he had something important to say\nhe did not",
                "everyone u pinged has already forgotten ur name",
                "mass pinging people is the discord equivalent of calling someone 15 times at 3am",
            ]

        else:
            title = "💀 caught lackin"
            jokes = [
                "ur message got deleted bro\nwe also reported u to ur mom\nshe said shes disappointed (again)",
                "deleted. gone. erased from history like it never happened\njust like ur social life",
                "bro really said that\nin THIS server\nin THAT channel\nbold move. wrong move.",
                "the audacity. the nerve. the absolute disrespect.\ntimed out.",
                "we have seen some things in this server\nbut this? this was something else\ngoodbye",
            ]

        joke = random.choice(jokes)

        try:
            warn_embed = discord.Embed(
                title=title,
                description=f"{message.author.mention} {joke}",
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
