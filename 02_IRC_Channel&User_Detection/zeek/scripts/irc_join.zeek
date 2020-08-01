@load base/bif/plugins/Zeek_IRC.events.bif.zeek

module Strato6;

type irc_join_record: record {
    ts: time &log;
    orig_h: addr &log;
    orig_p: port &log;
    resp_h: addr &log;
    resp_p: port &log;

    nick: string &log; # L2 source (if Ethernet).
    channel: string &log; # L2 destination (if Ethernet).
    password: string &log;
    usermode: string &log;
};

global irc_join_vec: vector of irc_join_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato6::LOG, [$columns=irc_join_record, $path="irc_join"]);
}

event zeek_done() {
   for (i in irc_join_vec) {
       Log::write( Strato6::LOG, irc_join_vec[i]);
   }
}

# Command: JOIN
# Parameters: ( <channel> *( "," <channel> ) [ <key> *( "," <key> ) ] ) / "0"
# 
# The JOIN command is used by a user to request to start listening to
# the specific channel.  Servers MUST be able to parse arguments in the
# form of a list of target, but SHOULD NOT use lists when sending JOIN
# messages to clients.
# 
# Once a user has joined a channel, he receives information about
# all commands his server receives affecting the channel.  This
# includes JOIN, MODE, KICK, PART, QUIT and of course PRIVMSG/NOTICE.
# This allows channel members to keep track of the other channel
# members, as well as channel modes.
# 
# If a JOIN is successful, the user receives a JOIN message as
# confirmation and is then sent the channel's topic (using RPL_TOPIC) and
# the list of users who are on the channel (using RPL_NAMREPLY), which
# MUST include the user joining.
# 
# Examples:
# JOIN #foobar                    ; Command to join channel #foobar.
# JOIN &foo fubar                 ; Command to join channel &foo using key "fubar".
event irc_join_message(c: connection, is_orig: bool, info_list: irc_join_list) {
    for (el in info_list) {
        local rec: irc_join_record = irc_join_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p, $nick=el$nick, $usermode=el$usermode, $password=el$password, $channel= el$channel);
        irc_join_vec += rec;
    }
}