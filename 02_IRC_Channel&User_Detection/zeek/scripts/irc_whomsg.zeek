@load base/bif/plugins/Zeek_IRC.events.bif.zeek

module Strato18;

type irc_whomsg_record: record {
    ts: time &log;
    orig_h: addr &log;
    orig_p: port &log;
    resp_h: addr &log;
    resp_p: port &log;
    
    mask: string &log;
    oper: bool &log;
};

global irc_whomsg_vec: vector of irc_whomsg_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato18::LOG, [$columns=irc_whomsg_record, $path="irc_whomsg"]);
}

event zeek_done() {
   for (i in irc_whomsg_vec) {
       Log::write( Strato18::LOG, irc_whomsg_vec[i]);
   }
}

# Generated for IRC messages of type who. This event is generated for messages coming from both the client and the server.
# C:	The connection.
# Is_orig:	True if the command was sent by the originator of the TCP connection.
# Mask:	The mask specified in the message.
# Oper:	True if the operator flag was set.
event irc_who_message(c: connection, is_orig: bool, mask: string, oper: bool) {
    if (c?$irc) {
        local rec: irc_whomsg_record = irc_whomsg_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p, $mask=mask, $oper=oper);
        irc_whomsg_vec += rec;        
    }
}