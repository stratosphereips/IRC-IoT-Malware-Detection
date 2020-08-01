@load base/bif/plugins/Zeek_IRC.events.bif.zeek

module Strato3;

type irc_error_record: record {
    ts: time &log;
    orig_h: addr &log;
    orig_p: port &log;
    resp_h: addr &log;
    resp_p: port &log;
    
    prefix: string &log;
    message: string &log;
};

global irc_error_vec: vector of irc_error_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato3::LOG, [$columns=irc_error_record, $path="irc_error"]);
}

event zeek_done() {
   for (i in irc_error_vec) {
       Log::write( Strato3::LOG, irc_error_vec[i]);
   }
}


# Generated for IRC messages of type error. This event is generated for messages coming from both the client and the server.
# C:	The connection.
# Is_orig:	True if the command was sent by the originator of the TCP connection.
# Prefix:	The optional prefix coming with the command. IRC uses the prefix to indicate the true origin of a message.
# Message:	The textual description specified in the message.
event irc_error_message(c: connection, is_orig: bool, prefix: string, message: string) {
    if (c?$irc) {
        local rec: irc_error_record = irc_error_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p, $prefix=prefix, $message=message);
        irc_error_vec += rec;        
    }
}