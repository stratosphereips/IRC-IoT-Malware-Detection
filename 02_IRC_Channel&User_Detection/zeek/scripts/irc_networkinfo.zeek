@load base/bif/plugins/Zeek_IRC.events.bif.zeek

module Strato10;

type irc_networkinfo_record: record {
    ts: time &log;
    orig_h: addr &log;
    orig_p: port &log;
    resp_h: addr &log;
    resp_p: port &log;
    
    users: count &log;
    services: count &log;
    servers: count &log;
};

global irc_networkinfo_vec: vector of irc_networkinfo_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato10::LOG, [$columns=irc_networkinfo_record, $path="irc_networkinfo"]);
}

event zeek_done() {
   for (i in irc_networkinfo_vec) {
       Log::write( Strato10::LOG, irc_networkinfo_vec[i]);
   }
}

# Generated for an IRC reply of type luserclient.
# C:	The connection.
# Is_orig:	True if the command was sent by the originator of the TCP connection.
# Users:	The number of users as returned in the reply.
# Services:	The number of services as returned in the reply.
# Servers:	The number of servers as returned in the reply.
event irc_network_info(c: connection, is_orig: bool, users: count, services: count, servers: count) {
    if (c?$irc) {
        local rec: irc_networkinfo_record = irc_networkinfo_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p, $users=users, $services=services, $servers=servers);
        irc_networkinfo_vec += rec;        
    }
}
