#!/usr/bin/python

import telnetlib
import select
import sys
import logging
from logging.handlers import RotatingFileHandler
import time
import optparse
import os
import os.path
import ConfigParser
import getpass
import signal
import socket
import re


class BaseConfig:
    def __init__(self):
        self.host = "localhost"
        self.port = 23
        self.user = getpass.getuser()
        self.password = None
        self.login_prompt = "ogin:"
        self.password_prompt = "assword:"
        self.logged_phrase = None
        self.timeout = 5
        self.reconnect_delay = 5
        self.sig_usr1_cmd = None
        self.sig_usr2_cmd = None
        self.initial_cmd = None
        self.initial_cmd_error_phrase = None


class Config(BaseConfig):
    GLOBAL_SECTION = "global"

    def __init__(self):
        BaseConfig.__init__(self)
        # super(Config, self).__init__()
        self.filename = None
        self.max_logs = 1
        self.max_log_size = 100000
        self.cfg = ConfigParser.ConfigParser()
        self.wd_cmd = None
        self.wd_start_after_delay = None
        self.wd_start_after_phrase = None
        self.wd_delay = 30
        self.wd_max_wait = None
        self.wd_response = None

    def load_cfg_param(self, prop_name, var_name=None, section=GLOBAL_SECTION):
        if not var_name:
            var_name = prop_name
        if self.cfg.has_option(section, prop_name):
            value = self.cfg.get(section, var_name)
            self.__dict__[prop_name] = value

    def load_cfg_param_int(self, prop_name, var_name=None, section=GLOBAL_SECTION):
        if not var_name:
            var_name = prop_name
        if self.cfg.has_option(section, prop_name):
            value = self.cfg.getint(section, var_name)
            self.__dict__[prop_name] = value

    def load_cfg_params(self, section):
        self.load_cfg_param("host", section=section)
        self.load_cfg_param_int("port", section=section)
        self.load_cfg_param("user", section=section)
        self.load_cfg_param("password", section=section)
        self.load_cfg_param("filename", section=section)
        self.load_cfg_param_int("max_logs", section=section)
        self.load_cfg_param_int("max_log_size", section=section)
        self.load_cfg_param("login_prompt", section=section)
        self.load_cfg_param("password_prompt", section=section)
        self.load_cfg_param("wd_cmd", section=section)
        self.load_cfg_param_int("wd_start_after_delay", section=section)
        self.load_cfg_param("wd_start_after_phrase", section=section)
        self.load_cfg_param_int("wd_delay", section=section)
        self.load_cfg_param_int("wd_max_wait", section=section)
        self.load_cfg_param("wd_response", section=section)
        self.load_cfg_param("logged_phrase", section=section)
        self.load_cfg_param_int("timeout", section=section)
        self.load_cfg_param("sig_usr1_cmd", section=section)
        self.load_cfg_param("sig_usr2_cmd", section=section)
        self.load_cfg_param_int("reconnect_delay", section=section)
        self.load_cfg_param("initial_cmd", section=section)
        self.load_cfg_param("initial_cmd_error_phrase", section=section)

    def load_from_file(self, file_name):
        if self.cfg.read(file_name) == [file_name]:
            self.load_cfg_params(section=Config.GLOBAL_SECTION)
            if self.cfg.has_option(Config.GLOBAL_SECTION, "use"):
                section = self.cfg.get(Config.GLOBAL_SECTION, "use")
                self.load_cfg_params(section=section)

    def load_from_command_line(self, opts):
        for key in opts.__dict__:
            value = opts.__dict__[key]
            if value is not None:
                self.__dict__[key] = value


class Authenticator:
    def __init__(self, telnet_base, base_config):
        self.cfg = base_config
        self.telnet_base = telnet_base

    def debug(self, message, *args, **kwargs):
        self.telnet_base.info(message, *args, **kwargs)

    def authenticate(self):
        if self.cfg.login_prompt:
            self.debug("waiting for login prompt...")
            line = self.telnet_base.expect_line(self.cfg.login_prompt)
            self.debug("Sending login name...")
            self.telnet_base.write_line(self.cfg.user + "\n")
            self.debug("waiting for password prompt...")
            line = self.telnet_base.expect_line(self.cfg.password_prompt)
            self.debug("Sending password...")
            self.telnet_base.write_line(self.cfg.password + "\n")
        if self.cfg.logged_phrase:
            self.debug("waiting for logged in phrase")
            self.telnet_base.expect_line(self.cfg.logged_phrase, timeout=self.cfg.timeout * 5)
            self.debug("logged in")


DEFAULT_TIMEOUT = object()
DEFAULT_LISTENER = object()


class LineSource:
    """
    This is enum
    """
    REMOTE = 0
    LOCAL = 1
    MESSAGE = 2


class TimeoutException(Exception):
    pass


class LineListener:
    """
    this is abstract class
    """

    def on_line_received(self, line, telnet_base, source=LineSource.REMOTE, level=logging.INFO):
        pass


class LineFilter:
    """
    this is abstract class
    """

    def filter_line(self, line, telnet_base, source=LineSource.REMOTE):
        """

        :param line:
        :param telnet_base:
        :param source:
        :return: False if line should be dropped, True otherwise
        """
        return True


class TelnetBase:
    def __init__(self, conf, listener=DEFAULT_LISTENER, default_timeout=None):
        self.next_listener_id = 0
        self.next_filter_id = 0
        self.listeners = {}
        self.filters = {}
        if listener == DEFAULT_LISTENER:
            listener = ConsoleListener()
        if listener:
            self.add_listener(listener)
        self.conf = conf
        self.default_timeout = default_timeout
        self.telnet = telnetlib.Telnet(timeout=default_timeout)
        self.buffer = ""
        self.conf = conf
        self.cmd_to_send = None
        self.signal_pending = False

        # def debug(self, message, *params):
        # self.send_to_listeners(message.format(*params))

    def connect(self, authenticator=Authenticator):
        self.info("******************************")
        self.info("connecting to {}...", self.conf.host)
        self.info("******************************")
        self.telnet.open(host=self.conf.host, port=self.conf.port, timeout=self.conf.timeout)
        authenticator(self, self.conf).authenticate()
        self.initial_cmd()

    def disconnect(self):
        self.telnet.close()

    def add_listener(self, listener):
        listener_id = self.next_listener_id
        self.next_listener_id += 1
        self.listeners[listener_id] = listener
        return listener_id

    def add_filter(self, filter):
        filter_id = self.next_filter_id
        self.next_filter_id += 1
        self.filters[filter_id] = filter
        return filter_id

    def remove_listener(self, listener_id):
        del self.listeners[listener_id]

    def remove_filter(self, filter_id):
        del self.filters[filter_id]

    def expect_line(self, line_expected, timeout=DEFAULT_TIMEOUT):
        if timeout == DEFAULT_TIMEOUT:
            timeout = self.default_timeout
        index, match, line = self.telnet.expect(list=[line_expected], timeout=timeout)
        # self.debug("line received: {}".format(line))
        if index < 0:
            raise TimeoutException()
        return line

    def write_line(self, line):
        self.telnet.write(line)

    def writeln_line(self, line):
        self.telnet.write(line + "\n")


    def cmd_usr1(self):
        self.signal_pending = True
        if self.conf.sig_usr1_cmd:
            self.info("sending usr1_cmd: {}", self.conf.sig_usr1_cmd)
            self.cmd_to_send = self.conf.sig_usr1_cmd

    def cmd_usr2(self):
        self.signal_pending = True
        if self.conf.sig_usr2_cmd:
            self.info("sending usr2_cmd")
            self.cmd_to_send = self.conf.sig_usr2_cmd

    def initial_cmd(self):
        if self.conf.initial_cmd:
            self.info("sending initial_cmd")
            # self.writeln_line(self.conf.initial_cmd)
            self.cmd_to_send = self.conf.initial_cmd

    def watchdog_cmd(self):
        if self.conf.wd_cmd:
            self.debug("sending watchdog command")
            self.writeln_line(self.conf.wd_cmd)

    def send_pending_cmd(self):
        if self.cmd_to_send:
            pipe_pos = self.cmd_to_send.find("|")
            if pipe_pos > 0:
                cmd = self.cmd_to_send[:pipe_pos]
                self.cmd_to_send = self.cmd_to_send[pipe_pos + 1:]
            else:
                cmd = self.cmd_to_send
                self.cmd_to_send = None
            self.writeln_line(cmd)

    def wait_for_line(self):
        pass

    def send_to_listeners(self, line, source=LineSource.REMOTE, level=logging.INFO):
        for listener in self.listeners.values():
            listener.on_line_received(line, self, source, level)

    def process_filters(self, line, source=LineSource.REMOTE):
        for f in self.filters.values():
            if not f.filter_line(line, self, source):
                return False
        return True

    def debug(self, msg, *args, **kwargs):
        self.send_to_listeners(msg.format(*args, **kwargs), source=LineSource.MESSAGE, level=logging.DEBUG)

    def info(self, msg, *args, **kwargs):
        self.send_to_listeners(msg.format(*args, **kwargs), source=LineSource.MESSAGE, level=logging.INFO)

    def warning(self, msg, *args, **kwargs):
        self.send_to_listeners(msg.format(*args, **kwargs), source=LineSource.MESSAGE, level=logging.WARNING)

    def error(self, msg, *args, **kwargs):
        self.send_to_listeners(msg.format(*args, **kwargs), source=LineSource.MESSAGE, level=logging.ERROR)

    def __process_remote_data(self):
        try:
            text = self.telnet.read_eager()
        except EOFError:
            print '*** Connection closed by remote host ***'
            raise
        if text:
            self.buffer += text
            while True:
                nl_index = self.buffer.find("\n")
                if nl_index < 0:
                    break
                line = self.buffer[:nl_index].strip("\r\n")
                # "".str
                self.buffer = self.buffer[nl_index + 1:]
                # print "[", text, "] [",line,"] [", self.buffer, "]"
                if line:
                    if self.process_filters(line, source=LineSource.REMOTE):
                        self.send_to_listeners(line)


    def process_remote_data(self, local_fd=None, timeout=None):
        in_fd = [self.telnet]
        if local_fd:
            in_fd.append(local_fd)
        try:
            rfd, wfd, xfd = select.select(in_fd, [], [], timeout)
        except select.error:
            # SIGUSR1 and SIGUSR2 signals interrupts select call. There is no way to identify that EINTR was a reason
            # so flag is used instead. We don't want to reconnect in that case so we simple return from this method
            if self.signal_pending:
                self.signal_pending = False
                return
            else:
                raise
        if self.telnet in rfd:
            self.__process_remote_data()
        if local_fd in rfd:
            line = local_fd.readline()
            if line:
                self.write_line(line)
                self.send_to_listeners(line, source=LineSource.LOCAL)


class LoggerListener(LineListener):
    def __init__(self, filename, max_bytes, backup_count):
        self.logger = logging.getLogger("telnet")
        rfh = RotatingFileHandler(filename=filename, maxBytes=max_bytes, backupCount=backup_count)
        rfh.setLevel(logging.INFO)
        rfh.setFormatter(logging.Formatter(fmt="%(asctime)s %(message)s"))
        self.logger.addHandler(rfh)
        self.logger.setLevel(logging.INFO)

    def on_line_received(self, line, telnet_base, source=LineSource.REMOTE, level=logging.INFO):
        self.logger.log(level, "%s", line)


class LogConsoleListener(LineListener):
    def __init__(self):
        pass

    def on_line_received(self, line, telnet_base, source=LineSource.REMOTE, level=logging.INFO):
        time_str = time.strftime("%c")
        if level >= logging.INFO:
            print("{}: {}".format(time_str, line))


class InitialCommandErrorPhraseListener(LineListener):
    def __init__(self, initial_cmd_error_phrase):
        self.patt = re.compile(initial_cmd_error_phrase)

    def on_line_received(self, line, telnet_base, source=LineSource.REMOTE, level=logging.INFO):
        if source == LineSource.REMOTE and self.patt.match(line):
            telnet_base.error("initial command failed. Will be resent")
            telnet_base.initial_cmd()


class ConsoleListener(LineListener):
    def __init__(self):
        pass

    def on_line_received(self, line, telnet_base, source=LineSource.REMOTE, level=logging.INFO):
        print("{}".format(line))


class SimpleFileListener(LineListener):
    def __init__(self):
        pass

    def on_line_received(self, line, telnet_base, source=LineSource.REMOTE, level=logging.INFO):
        with open(self.log_path, mode="a") as f:
            f.write(line)


class WatchdogListener(LineFilter):
    def __init__(self, wd_response_phrase, wd_timeout):
        self.wd_timeout = wd_timeout
        self.wd_response_phrase = wd_response_phrase
        self.wd_response_last_seen = None
        self.patt = re.compile(wd_response_phrase)

    def filter_line(self, line, telnet_base, source=LineSource.REMOTE):
        if source == LineSource.REMOTE and self.patt.match(line):
            self.reset()
            return False
        return True

    def is_expired(self):
        if not self.wd_response_last_seen:
            return False
        return time.time() - self.wd_response_last_seen >= self.wd_timeout

    def reset(self):
        self.wd_response_last_seen = time.time()


def get_cmd_params():
    op = optparse.OptionParser()
    op.add_option("-H", "--host", dest="host", help="target telnet host name (defaults to localhost)",
                  default=None)
    op.add_option("-P", "--port", dest="port", type="int",
                  help="destination connection port. (defaults to 23)", default=None)
    op.add_option("-u", "--user", dest="user", help="user name (defaults to current user)", default=None)
    op.add_option("-p", "--password", dest="password", help="password", default=None)
    op.add_option("--login-prompt", dest="login_prompt", help="login prompt to wait for (defaults to 'ogin:'",
                  default=None)
    op.add_option("--password-prompt", dest="password_prompt",
                  help="password prompt to wait for (defaults to 'assword:')",
                  default=None)
    op.add_option("--logged-phrase", dest="logged_phrase",
                  help="text phrase to be recognized as a successful login confirmation", default=None)
    op.add_option("--wd-cmd", dest="wd_cmd", help="'watchdog command' text to send to remote host periodically")
    op.add_option("--wd-start-after-delay", dest="wd_start_after_delay", type="int",
                  help="time after logged before start watchdog (not implemented yet)")
    op.add_option("--wd-start=after-phrase", dest="wd_start_after_phrase",
                  help="phrase in output after start watchdog (not implemented yet)")
    op.add_option("--wd-max-wait", dest="wd_max_wait", type="int",
                  help="maximum time to wait for watchdog response (not implemented yet)")
    op.add_option("--wd-response", dest="wd_response",
                  help="text phrase recognized as watchdog response (not implemented yet)")
    op.add_option("--sig-usr1-cmd", dest="sig_usr1_cmd",
                  help="command to be sent to remote side after receiving USR1 signal")
    op.add_option("--sig-usr2-cmd", dest="sig_usr2_cmd",
                  help="command to be sent to remote side after receiving USR2 signal")
    op.add_option("--wd-delay", dest="wd_delay", type="int", help="delay between successive sending watchdog commands")
    op.add_option("--initial-cmd", dest="initial_cmd", help="command to be sent to remote host after login")
    op.add_option("--initial-cmd-error-phrase", dest="initial_cmd_error_phrase",
                  help="remote response phrase to resend initial command")
    op.add_option("--reconnect-delay", dest="reconnect_delay", type="int",
                  help="delay after connection lost/error and retry")
    op.add_option("--filename", dest="filename",
                  help="filename of a log file")
    op.add_option("-c", "--cfg", dest="cfg", help="configuration file (defaults to ~/telnet_logger.ini", default=None)
    opts, args = op.parse_args()
    return opts, args


class TelnetLogger(TelnetBase):
    def __init__(self, conf):
        # self.conf = Config()
        TelnetBase.__init__(self, conf=conf, default_timeout=conf.timeout, listener=None)
        self.log_path = conf.filename
        self.has_output = False
        if self.log_path:
            self.logger_listener = LoggerListener(conf.filename, conf.max_log_size, conf.max_logs)
            self.add_listener(self.logger_listener)
            self.has_output = True
        # if sys.stdin.isatty():
        self.console_listener = LogConsoleListener()
        self.add_listener(self.console_listener)
        self.has_output = True
        self.wd = None
        if self.conf.wd_response:
            self.wd = WatchdogListener(wd_response_phrase=self.conf.wd_response, wd_timeout=self.conf.wd_max_wait)
            self.add_filter(self.wd)
        if self.conf.initial_cmd_error_phrase:
            self.add_listener(InitialCommandErrorPhraseListener(self.conf.initial_cmd_error_phrase))


class Global:
    telnet = None


def sig_usr1(signum, frame):
    if (Global.telnet):
        Global.telnet.cmd_usr1()


def sig_usr2(signum, frame):
    if (Global.telnet):
        Global.telnet.cmd_usr2()


def main():
    opts, args = get_cmd_params()
    if not opts.cfg:
        opts.cfg = os.path.expanduser("~/telnet_logger.ini")
    c = Config()
    c.load_from_file(opts.cfg)
    c.load_from_command_line(opts)
    if c.password_prompt and not c.password:
        if not sys.stdin.isatty():
            print "cannot retrieve password in batch mode!! aborting"
            sys.exit(1)
        c.password = getpass.getpass(prompt="password for telnet session:")
    telnet = TelnetLogger(conf=c)
    Global.telnet = telnet
    signal.signal(signal.SIGUSR1, sig_usr1)
    signal.signal(signal.SIGUSR2, sig_usr2)
    local_fd = None
    if sys.stdin.isatty() or True:
        local_fd = sys.stdin
    while True:
        try:
            telnet.connect()
            if telnet.wd:
                telnet.wd.reset()
            wd_time = time.time()
            while True:
                telnet.send_pending_cmd()
                telnet.process_remote_data(local_fd=local_fd, timeout=4)
                ctime = time.time()
                if c.wd_cmd and c.wd_delay and ctime > wd_time + c.wd_delay:
                    telnet.watchdog_cmd()
                    wd_time = time.time()
                if telnet.wd and telnet.wd.is_expired():
                    telnet.error("==========================================================")
                    telnet.error("remote host is not responding. Reconnecting in progress...")
                    telnet.error("==========================================================")
                    telnet.disconnect()
                    break

        except socket.error as e:
            telnet.error("error during connection: {} {}. Retrying after {} seconds...", e.__class__, e.strerror,
                         c.reconnect_delay)
            # raise
            time.sleep(c.reconnect_delay)
        except Exception as e:
            telnet.error("error during connection: {} {}. Retrying after {} seconds...", e.__class__, e.message,
                         c.reconnect_delay)
            # raise
            time.sleep(c.reconnect_delay)


if __name__ == '__main__':
    main()
