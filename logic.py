import logging
from telegram import Update, ForceReply
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext

from scanner import ip_scanner, cidr_reverse_ip, tls_scanner, file_scanner, proxy_scanner, domain_extractor, custom_port_scanning, payload_maker

# Enable logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)
logger = logging.getLogger(__name__)

# Define the bot token and command handlers
TOKEN = 'YOUR_BOT_TOKEN'
updater = Updater(TOKEN, use_context=True)
dispatcher = updater.dispatcher

def start(update: Update, context: CallbackContext) -> None:
    user = update.message.from_user
    logger.info("User %s started the conversation.", user.first_name)
    update.message.reply_text('Hi! Send me a CIDR range to scan for live IPs.')

def ip_scanner_handler(update: Update, context: CallbackContext) -> None:
    cidr_range = update.message.text
    targets = ip_scanner(cidr_range)
    update.message.reply_text(f"Live IPs: {targets}")

def cidr_reverse_ip_handler(update: Update, context: CallbackContext) -> None:
    cidr_range = update.message.text
    update.message.reply_text(cidr_reverse_ip(cidr_range))

def tls_scanner_handler(update: Update, context: CallbackContext) -> None:
    targets = ip_scanner(update.message.text)
    open_ports = tls_scanner(targets)
    update.message.reply_text(f"Open TLS ports: {open_ports}")

def file_scanner_handler(update: Update, context: CallbackContext) -> None:
    file_path = update.message.text
    targets = file_scanner(file_path)
    update.message.reply_text(f"Live IPs from file: {targets}")

def proxy_scanner_handler(update: Update, context: CallbackContext) -> None:
    targets = ip_scanner(update.message.text)
    proxies = proxy_scanner(targets)
    update.message.reply_text(f"Active proxies: {proxies}")

def domain_extractor_handler(update: Update, context: CallbackContext) -> None:
    text = update.message.text
    domains = domain_extractor(text)
    update.message.reply_text(f"Extracted domains: {domains}")

def custom_port_scanning_handler(update: Update, context: CallbackContext) -> None:
    targets = ip_scanner(update.message.text)
    port = int(context.args[0])
    method = context.args[1]
    payload = context.args[2] if len(context.args) > 2 else None
    custom_results = custom_port_scanning(targets, port, method, payload)
    update.message.reply_text(f"Custom port scan results: {custom_results}")

def payload_maker_handler(update: Update, context: CallbackContext) -> None:
    proxy_type = context.args[0]
    user = context.args[1]
    password = context.args[2]
    payload = payload_maker(proxy_type, user, password)
    update.message.reply_text(f"Payload: {payload}")

# Add command handlers to the bot
start_handler = CommandHandler('start', start)
ip_scanner_handler = MessageHandler(Filters.regex(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$'), ip_scanner_handler)
cidr_reverse_ip_handler = MessageHandler(Filters.regex(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$'), cidr_reverse_ip_handler)
tls_scanner_handler = MessageHandler(Filters.regex(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$'), tls_scanner_handler)
file_scanner_handler = MessageHandler(Filters.regex(r'^.*\.txt$'), file_scanner_handler)
proxy_scanner_handler = MessageHandler(Filters.regex(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$'), proxy_scanner_handler)
domain_extractor_handler = MessageHandler(Filters.text & (~Filters.command), domain_extractor_handler)
custom_port_scanning_handler = MessageHandler(Filters.regex(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}\s+\d+\s+\w+(\s+(.+))?$'), custom_port_scanning_handler)
payload_maker_handler = MessageHandler(Filters.regex(r'^(\w+)\s+(\w+)\s+(\w+)$'), payload_maker_handler)

dispatcher.add_handler(start_handler)
dispatcher.add_handler(ip_scanner_handler)
dispatcher.add_handler(cidr_reverse_ip_handler)
dispatcher.add_handler(tls_scanner_handler)
dispatcher.add_handler(file_scanner_handler)
dispatcher.add_handler(proxy_scanner_handler)
dispatcher.add_handler(domain_extractor_handler)
dispatcher.add_handler(custom_port_scanning_handler)
dispatcher.add_handler(payload_maker_handler)

# Start the bot
updater.start_polling()
updater.idle()
