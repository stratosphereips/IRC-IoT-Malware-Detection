module Strato13;

type irc_privmsg_record: record {
   ts: time &log;
   orig_h: addr &log;
   orig_p: port &log;
   resp_h: addr &log;
   resp_p: port &log;
   
   source: string &log;
   target: string &log;
   msg: string &log;
};


global irc_privmsg_vec: vector of irc_privmsg_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato13::LOG, [$columns=irc_privmsg_record, $path="irc_privmsg"]);
}

event zeek_done() {
   for (i in irc_privmsg_vec) {
       Log::write( Strato13::LOG, irc_privmsg_vec[i]);
   }
}

# Command: PRIVMSG
# Parameters: <msgtarget> <text to be sent>
# 
# PRIVMSG is used to send private messages between users, as well as to
# send messages to channels.  <msgtarget> is usually the nickname of
# the recipient of the message, or a channel name.
# 
# The <msgtarget> parameter may also be a host mask (#<mask>) or server
# mask ($<mask>).  In both cases the server will only send the PRIVMSG
# to those who have a server or host matching the mask.  The mask MUST
# have at least 1 (one) "." in it and no wildcards following the last
# ".".  This requirement exists to prevent people sending messages to
# "#*" or "$*", which would broadcast to all users.  Wildcards are the
# '*' and '?'  characters.  This extension to the PRIVMSG command is
# only available to operators.
event irc_privmsg_message(c: connection, is_orig: bool, source: string, target: string, message: string) {
   if (c?$irc) {
      local rec: irc_privmsg_record = irc_privmsg_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p, $source=source, $target=target, $msg=message);
      irc_privmsg_vec += rec;
   }
}
