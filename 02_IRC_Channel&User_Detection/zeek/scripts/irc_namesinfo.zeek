module Strato9;

type irc_namesinfo_record: record {
    ts: time &log;
    orig_h: addr &log;
    orig_p: port &log;
    resp_h: addr &log;
    resp_p: port &log;
    
    c_type:string &log; 
    channel: string &log;
    users: string &log;
};

global irc_namesinfo_vec: vector of irc_namesinfo_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato9::LOG, [$columns=irc_namesinfo_record, $path="irc_namesinfo"]);
}

event zeek_done() {
   for (i in irc_namesinfo_vec) {
       Log::write( Strato9::LOG, irc_namesinfo_vec[i]);
   }
}

event irc_names_info(c: connection, is_orig: bool, c_type: string, channel: string, users: string_set) {
    local users_log : string = "";
    for (user in users) {
        users_log += user + ",";
    }

    local rec: irc_namesinfo_record = irc_namesinfo_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p, $c_type=c_type, $channel=channel, $users=users_log);
    irc_namesinfo_vec += rec;        
}