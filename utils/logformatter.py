#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -------------------------------------------------------------------------------
#                                                                               -
#  Python dual-logging setup (console and log file),                            -
#  supporting different log levels and colorized output                         -
#                                                                               -
#  Created by Fonic <https://github.com/fonic>                                  -
#  Date: 04/05/20                                                               -
#                                                                               -
#  Based on:                                                                    -
#  https://stackoverflow.com/a/13733863/1976617                                 -
#  https://uran198.github.io/en/python/2016/07/12/colorful-python-logging.html  -
#  https://en.wikipedia.org/wiki/ANSI_escape_code#Colors                        -
#                                                                               -
# -------------------------------------------------------------------------------

# Imports
import os
import sys
import logging

# Logging formatter supporting colored output
class LogFormatter(logging.Formatter):

    COLOR_CODES = {
        logging.CRITICAL: "\033[1;31m", # bright/bold red
        logging.ERROR:    "\033[1;31m", # bright/bold red
        logging.WARNING:  "\033[1;33m", # bright/bold yellow
        logging.INFO:     "\033[0;37m", # white / light gray
        logging.DEBUG:    "\033[1;30m"  # bright/bold black / dark gray
    }

    RESET_CODE = "\033[0m"

    def __init__(self, color, *args, **kwargs):
        super(LogFormatter, self).__init__(*args, **kwargs)
        self.color = color

    def format(self, record, *args, **kwargs):
        if (self.color == True and record.levelno in self.COLOR_CODES):
            record.color_on  = self.COLOR_CODES[record.levelno]
            record.color_off = self.RESET_CODE
        else:
            record.color_on  = ""
            record.color_off = ""
        return super(LogFormatter, self).format(record, *args, **kwargs)

# Setup logging
def _setup_logging(console_log_output, console_log_level, console_log_color, console_format, logfile_file, logfile_mode, logfile_log_level, logfile_log_color, logfile_format):

    # Create logger
    # For simplicity, we use the root logger, i.e. call 'logging.getLogger()'
    # without name argument. This way we can simply use module methods for
    # for logging throughout the script. An alternative would be exporting
    # the logger, i.e. 'global logger; logger = logging.getLogger("<name>")'
    logger = logging.getLogger()

    # Set global log level to 'debug' (required for handler levels to work)
    logger.setLevel(logging.DEBUG)

    # Create console handler
    console_log_output = console_log_output.lower()
    if (console_log_output == "stdout"):
        console_log_output = sys.stdout
        console_handler = logging.StreamHandler(console_log_output)
    elif (console_log_output == "stderr"):
        console_log_output = sys.stderr
        console_handler = logging.StreamHandler(console_log_output)
    else:
        try:
            console_handler = logging.FileHandler(console_log_output, mode=logfile_mode)
        except Exception as exception:
            print("Failed to set up log file: %s" % str(exception))
            return False



    # Set console log level
    try:
        console_handler.setLevel(console_log_level.upper()) # only accepts uppercase level names
    except:
        print("Failed to set console log level: invalid level: '%s'" % console_log_level)
        return False

    # Create and set formatter, add console handler to logger
    console_formatter = LogFormatter(fmt=console_format, color=console_log_color)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Create log file handler
    try:
        logfile_handler = logging.FileHandler(logfile_file, mode=logfile_mode)
    except Exception as exception:
        print("Failed to set up log file: %s" % str(exception))
        return False

    # Set log file log level
    try:
        logfile_handler.setLevel(logfile_log_level.upper()) # only accepts uppercase level names
    except:
        print("Failed to set log file log level: invalid level: '%s'" % logfile_log_level)
        return False

    # Create and set formatter, add log file handler to logger
    logfile_formatter = LogFormatter(fmt=logfile_format, color=logfile_log_color)
    logfile_handler.setFormatter(logfile_formatter)
    logger.addHandler(logfile_handler)

    # Success
    return True


# Enable ANSI terminal on Microsoft Windows (Windows 10 only)
# https://stackoverflow.com/a/36760881/1976617
# https://docs.microsoft.com/en-us/windows/console/setconsolemode
def _windows_enable_ansi_terminal():
    import ctypes
    kernel32 = ctypes.windll.kernel32
    result = kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    if (result == 0): raise Exception


def start_logging(console_file="stdout", console_color=True, log_level="INFO"):

    _setup_logging(
        console_log_output=console_file,
        console_log_level=log_level, 
        console_log_color=console_color,
        console_format="%(color_on)s[%(levelname)s] %(message)s%(color_off)s",
        logfile_file="WSTT.log",
        logfile_mode="w",
        logfile_log_level="DEBUG",
        logfile_log_color=False,
        logfile_format="%(color_on)s[%(asctime)s] [%(levelname)s] %(name)s: %(message)s%(color_off)s"
    )
    if (sys.platform == "win32"):
        try:
            _windows_enable_ansi_terminal()
        except:
            logging.debug("Could not enable Windows ANSI terminal")
            

logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("selenium").setLevel(logging.WARNING)
logging.getLogger('chardet').setLevel(logging.INFO)
logging.getLogger('bs4').setLevel(logging.ERROR)