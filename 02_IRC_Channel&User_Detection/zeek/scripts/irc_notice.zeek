@load base/bif/plugins/Zeek_IRC.events.bif.zeek

module Strato12;

type irc_notice_record: record {
    ts: time &log;
    orig_h: addr &log;
    orig_p: port &log;
    resp_h: addr &log;
    resp_p: port &log;
    
    source: string &log;
    target: string &log;
    message: string &log;
};

global irc_notice_vec: vector of irc_notice_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato12::LOG, [$columns=irc_notice_record, $path="irc_notice"]);
}

event zeek_done() {
   for (i in irc_notice_vec) {
       Log::write( Strato12::LOG, irc_notice_vec[i]);
   }
}

# Generated for IRC messages of type notice. This event is generated for messages coming from both the client and the server.
# C:	The connection.
# Is_orig:	True if the command was sent by the originator of the TCP connection.
# Source:	The source of the private communication.
# Target:	The target of the private communication.
# Message:	The text of communication.
event irc_notice_message(c:connection, is_orig: bool, source: string, target: string, message: string) {
    if (c?$irc) {
        local rec: irc_notice_record = irc_notice_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p, $source=source, $target=target,$message=message);
        irc_notice_vec += rec;
    }
}