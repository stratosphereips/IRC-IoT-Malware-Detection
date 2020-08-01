@load scripts/irc_channelinfo.zeek
@load scripts/irc_channeltopic.zeek
@load scripts/irc_error.zeek
@load scripts/irc_globalusers.zeek
@load scripts/irc_invalidnick.zeek
@load scripts/irc_join.zeek
@load scripts/irc_kick.zeek
@load scripts/irc_modemsg.zeek
@load scripts/irc_namesinfo.zeek
@load scripts/irc_networkinfo.zeek
@load scripts/irc_nick.zeek
@load scripts/irc_notice.zeek
@load scripts/irc_privmsg.zeek
@load scripts/irc_usermsg.zeek
@load scripts/irc_who.zeek
@load scripts/irc_whois.zeek
@load scripts/irc_whoischannel.zeek
@load scripts/irc_whomsg.zeek


module Strato;

# Generated for IRC messages of type dcc. This event is generated for messages coming from both the client and the server.
# C:	The connection.
# Is_orig:	True if the command was sent by the originator of the TCP connection.
# Prefix:	The optional prefix coming with the command. IRC uses the prefix to indicate the true origin of a message.
# Target:	The target specified in the message.
# Dcc_type:	The DCC type specified in the message.
# Argument:	The argument specified in the message.
# Address:	The address specified in the message.
# Dest_port:	The destination port specified in the message.
# Size:	The size specified in the message.
event irc_dcc_message(c: connection, is_orig: bool, prefix: string, target: string, dcc_type: string, argument: string, address: addr, dest_port: count, size: count) {
    print "dcc message";
}

# Generated for IRC messages of type oper. This event is generated for messages coming from both the client and the server.
# C:	The connection.
# Is_orig:	True if the command was sent by the originator of the TCP connection.
# User:	The user specified in the message.
# Password:	The password specified in the message.
event irc_oper_message(c: connection, is_orig: bool, user: string, password: string) {
    print "oper message";
}

event irc_starttls(c: connection) {
    print "start tls";
}


# Generated for IRC replies of type youreoper and nooperhost.
# C:	The connection.
# Is_orig:	True if the command was sent by the originator of the TCP connection.
# Got_oper:	True if the oper command was executed successfully (youreport) and false otherwise (nooperhost).
event irc_oper_response(c: connection, is_orig: bool, got_oper: bool) {
    print "oper response";
}


# Command: INVITE
# Parameters: <nickname> <channel>
# 
# The INVITE command is used to invite a user to a channel.  The
# parameter <nickname> is the nickname of the person to be invited to
# the target channel <channel>.  There is no requirement that the
# channel the target user is being invited to must exist or be a valid
# channel.  However, if the channel exists, only members of the channel
# are allowed to invite other users.  When the channel has invite-only
# flag set, only channel operators may issue INVITE command.
event irc_invite_message(c: connection, is_orig: bool, prefix: string, nickname: string, channel: string) {
    print "invite message";
}

event irc_whois_operator_line(c: connection, is_orig: bool, nick: string) {
    print "whois operator line";   
}

