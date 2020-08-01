module Strato14;

type irc_usermsg_record: record {
    ts: time &log;
    orig_h: addr &log;
    orig_p: port &log;
    resp_h: addr &log;
    resp_p: port &log;

    user: string &log;
    host: string &log;
    server:string &log; 
    real_name: string &log;
};

global irc_usermsg_vec: vector of irc_usermsg_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato14::LOG, [$columns=irc_usermsg_record, $path="irc_usermsg"]);
}

event zeek_done() {
   for (i in irc_usermsg_vec) {
       Log::write( Strato14::LOG, irc_usermsg_vec[i]);
   }
}

# Command: USER
# Parameters: <username> <hostname> <servername> <realname>
# 
# The USER message is used at the beginning of connection to specify
# the username, hostname, servername and realname of s new user.  It is
# also used in communication between servers to indicate new user
# arriving on IRC, since only after both USER and NICK have been
# received from a client does a user become registered. 
# 
# The <mode> parameter should be a numeric, and can be used to
# automatically set user modes when registering with the server.  This
# parameter is a bitmask, with only 2 bits having any signification: if
# the bit 2 is set, the user mode 'w' will be set and if the bit 3 is
# set, the user mode 'i' will be set.  (See Section 3.1.5 "User
# Modes").
event irc_user_message(c: connection, is_orig: bool, user: string, host: string, server: string, real_name: string) {
    if (c?$irc) {
        local rec: irc_usermsg_record = irc_usermsg_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p, $user=user, $host=host, $server=server, $real_name=real_name);
        irc_usermsg_vec += rec;
    }
}