import os
import re

from dataclasses import dataclass
from enum import Enum
from types import TracebackType
from typing import Match, Optional, Type

import serial

from mariner import config
from mariner.exceptions import UnexpectedPrinterResponse
from mariner.exceptions import UnexpectedResponseLineNumber

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class PrinterState(Enum):
    IDLE = "IDLE"
    STARTING_PRINT = "STARTING_PRINT"
    PRINTING = "PRINTING"
    PAUSED = "PAUSED"
    CLOSED = "CLOSED"


@dataclass(frozen=True)
class PrintStatus:
    state: PrinterState
    current_byte: Optional[int] = None
    total_bytes: Optional[int] = None


class ChiTuPrinter:
    _serial_port: serial.Serial
    # used to compensate for being unable to determine pause when M4000 cannot be used.
    _printer_Status: PrintStatus
    # set to stop using  M4000 range of commands
    _exclude4000 = False
    # used to compensate for being unable to get file being pronted when M4006
    # cannot be used.
    _printName = ""
    # used to compensate for being unable to get file being pronted when M4006
    # cannot be used.
    _totalbyteCount = 0
    # the line number of the next response we'll receive
    _lineCount = 1
    # Track serial / printer connection status to allow disconnects
    _is_connected = False

    def __init__(self) -> None:
        self._serial_port = serial.Serial(
            baudrate=config.get_printer_baudrate(),
            timeout=0.1,
        )
        self._printer_Status = PrintStatus(state=PrinterState.IDLE)

    def _extract_response_with_regex(self, regex: str, data: str) -> Match[str]:
        match = re.search(regex, data)
        if match is None:
            raise UnexpectedPrinterResponse(data)
        return match

    def open(self) -> None:
        try:
            self._serial_port.port = config.get_printer_serial_port()
            self._serial_port.open()
            logger.debug("Debug Level Logging Started for Chitu Printer")
            self._lineCount = 1
            self.reset_line_number()
            self._is_connected = True
        except:
            self._is_connected = False

    def close(self) -> None:
        if self._is_connected:
            self._serial_port.close()
        

    def __enter__(self) -> "ChiTuPrinter":
        self.open()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> bool:
        self.close()
        return False

    def get_firmware_version(self) -> str:
        logger.debug("Obtain the Firmware Version Command Requested")
        data = self._send_and_read(b"M4002")
        return self._extract_response_with_regex(
            "^ok ([a-zA-Z0-9_.]+)\n$", data).group(1)

    def get_state(self) -> str:
        logger.debug("Obtain State Command Requested")
        return self._send_and_read(b"M4000")

    def get_print_status(self) -> PrintStatus:
        logger.debug("Obtain Print Status Command Requested")
        current_byte = 0
        total_bytes = 0
        if self._is_connected:
            if not self._exclude4000:
                data = self._send_and_read(b"M4000")
                if data == "ok":
                    # The response has been parsed and an ok with the correct line
                    # number has been received This means that the it is likely to
                    # be Firmware 4.4.3 which does not support M4000
                    self._exclude4000 = True
                    logger.debug(
                        "Disabling M400n commands because it seems" +
                        " printer does not support them.")
                else:
                    match = self._extract_response_with_regex(
                        "D:([0-9]+)/([0-9]+)/([0-9]+)", data)

                    current_byte = int(match.group(1))
                    total_bytes = int(match.group(2))
                    is_paused = match.group(3) == "1"

            if self._exclude4000:
                data = self._send_and_read(b"M27")
                logger.debug(f"M27 response = {data}")
                if "not printing now!" not in data:
                    match = self._extract_response_with_regex(
                            "byte ([0-9]+)/([0-9]+)", data)
                    current_byte = int(match.group(1))
                    total_bytes = int(match.group(2))
                    self._totalbyteCount = total_bytes
                    # can't tell from M27 if the printer is paused so we use our own copy of
                    # the status. This will obviously be a problem if Mariner is started up
                    # and the printer is already paused.
                    is_paused = self._printer_Status.state == PrinterState.PAUSED
                else:
                    total_bytes = 0

            if total_bytes == 0:
                self._printer_Status = PrintStatus(state=PrinterState.IDLE)
                return PrintStatus(state=PrinterState.IDLE)

            if current_byte == 0:
                self._printer_Status = PrintStatus(state=PrinterState.STARTING_PRINT)
                state = PrinterState.STARTING_PRINT
            elif is_paused:
                self._printer_Status = PrintStatus(state=PrinterState.PAUSED)
                state = PrinterState.PAUSED
            else:
                self._printer_Status = PrintStatus(state=PrinterState.PRINTING)
                state = PrinterState.PRINTING
        else:
            state = PrinterState.CLOSED

        return PrintStatus(
            state=state,
            current_byte=current_byte,
            total_bytes=total_bytes,
        )

    def get_z_pos(self) -> float:
        logger.debug("Obtain the Z position Command Requested")
        data = self._send_and_read(b"M114")
        return float(self._extract_response_with_regex("Z:([0-9.]+)", data).group(1))

    def reset_line_number(self) -> None:
        logger.debug("Resetting Line Number Command Requested")
        # The first response we get after a reset is line number 2
        self._lineCount = 2
        self._send_and_read(b"M110 N0")

    def get_selected_file(self) -> str:
        if not self._is_connected:
            return ""

        if not self._exclude4000:
            logger.debug("Obtain the Selected File Command Requested")
            data = self._send_and_read(b"M4006")
            if data == "ok":
                # The response has been parsed and an ok with the correct line number
                # has been received. This means that the it is likely to be Firmware
                # 4.4.3 which does not support M4006
                self._exclude4000 = True
                logger.debug(
                    "Disabling M400n commands because " +
                    "it seems printer does not support them.")
            selected_file = str(
                self._extract_response_with_regex("ok '([^']+)'\r\n", data).group(1))
            # normalize the selected file by removing the leading slash, which is
            # sometimes returned by the printer
            return re.sub("^/", "", selected_file)
        else:
            if self._printName == "":
                logger.debug(f"Looking for a file with size {self._totalbyteCount}")
                directory = os.fsencode(config.get_files_directory())
                for file in os.listdir(directory):
                    if os.stat(os.path.join(directory, 
                        file)).st_size == self._totalbyteCount:
                        logger.debug(
                            f"found {os.fsdecode(file)} -" +
                            f"{str(os.stat(os.path.join(directory, file)).st_size)}")
                        self._printName = os.fsdecode(file)
                        break
            return self._printName

    def select_file(self, filename: str) -> None:
        logger.debug("Select File Command Requested")
        response = self._send_and_read((f"M23 /{filename}").encode())
        if "File opened" not in response and "File selected" not in response:
            raise UnexpectedPrinterResponse(response)

    def move_by(self, z_dist_mm: float, mm_per_min: int = 600) -> None:
        logger.debug("Move Relative Command Requested")
        response = self._send_and_read(
            (f"G0 Z{z_dist_mm:.1f} F{mm_per_min} I0").encode()
        )
        if "ok" not in response:
            raise UnexpectedPrinterResponse(response)

    def move_to(self, z_pos: float) -> str:
        logger.debug("Move to Position Command Requested")
        return self._send_and_read((f"G0 Z{z_pos:.1f}").encode())

    def move_to_home(self) -> None:
        logger.debug("Move to Home Command Requested")
        response = self._send_and_read(b"G28")
        if "ok" not in response:
            raise UnexpectedPrinterResponse(response)

    def start_printing(self, filename: str) -> None:
        logger.debug("Start Printing Commands Requested")
        # the printer's firmware is weird when the file is in a subdirectory. we need to
        # send M23 to select the file with its full path and then M6030 with just the
        # basename.
        self.select_file(filename)
        self._printName = filename
        response = self._send_and_read(
            (f"M6030 '{os.path.basename(filename)}'").encode(),
            # the mainboard takes longer to reply to this command, so we override the
            # timeout to 2 seconds
            timeout_secs=2.0,
        )
        if "ok" not in response:
            raise UnexpectedPrinterResponse(response)

    def pause_printing(self) -> None:
        logger.debug("Pause Print Command Requested")
        response = self._send_and_read(b"M25")
        if "ok" not in response:
            raise UnexpectedPrinterResponse(response)
        self._printer_Status = PrintStatus(state=PrinterState.PAUSED)

    def resume_printing(self) -> None:
        logger.debug("Resume Print Command Requested")
        response = self._send_and_read(b"M24")
        if "ok" not in response:
            raise UnexpectedPrinterResponse(response)

    def stop_printing(self) -> None:
        logger.debug("Stop Printing Command Requested")
        response = self._send_and_read(b"M33")
        if "Er" in response:
            raise UnexpectedPrinterResponse(response)

    def stop_motors(self) -> None:
        logger.debug("Stop Motor Command Requested")
        response = self._send_and_read(b"M112")
        if "ok" not in response:
            raise UnexpectedPrinterResponse(response)

    def reboot(self, delay_in_ms: int = 0) -> None:
        logger.debug("Printer Reboot Requested")
        self._printName = ""
        self._send((f"M6040 I{delay_in_ms}").encode())

    def _obtain_line_number(self, response: str) -> str:
        # relevant responses contain a line number
        parsedResponse = self._extract_response_with_regex(
            "^([ESo][rDk]).N:([0-9.]+)\r\n", response)
        responseLineCount = int(parsedResponse.group(2))
        if responseLineCount != self._lineCount:
            tmpLineCount = self._lineCount
            self._lineCount = responseLineCount + 1
            raise UnexpectedResponseLineNumber(
                str(responseLineCount), str(tmpLineCount))
        else:
            logger.debug(f"Line # is {responseLineCount}")
            if parsedResponse.group(1) == "ok":
                # only increment the line counter for ok
                self._lineCount += 1
        return parsedResponse.group(1)

    def _send_and_read(self, data: bytes,
                       timeout_secs: Optional[float] =
                       None) -> str:
        self._send(data + b"\r\n")
        return self._read_response(timeout_secs)

    def _send(self, data: bytes) -> None:
        self._serial_port.write(data)
        logger.debug(data)
        # we're only interested in the response to the command we have just sent,
        # so there is no point reading until we know it has been sent.
        self._serial_port.flush()

    def _read_response(self, timeout_secs: Optional[float] = None) -> str:
        responseData = ""
        original_timeout = self._serial_port.timeout
        if timeout_secs is not None:
            self._serial_port.timeout = timeout_secs
        readSerialData = True
        while readSerialData:
            response = self._serial_port.readline().decode('utf-8')
            if response == "":
                readSerialData = False

            elif response == "ok":
                response = ""  # discard heart beats
            elif " N:" in response:
                rspCode = self._obtain_line_number(response)
                # if we have a line number, then it can either be for an "ok"
                # "Er" or "SD" (from my observations)
                logger.debug(f"Line Numbered response code is {rspCode}")
            else:
                responseData += response
                response = ""
        if timeout_secs is not None:
            self._serial_port.timeout = original_timeout
        logger.debug(f"Full Response Message:\r\n{responseData}")
        response = "ok" if responseData == "" else responseData
        return response
