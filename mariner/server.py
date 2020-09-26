import os
import logging
from enum import Enum

from flask import Flask, jsonify, render_template, request
from flask_caching import Cache
from pyre_extensions import none_throws
from waitress import serve
from whitenoise import WhiteNoise

from mariner.config import FILES_DIRECTORY
from mariner.file_formats.ctb import CTBFile
from mariner.mars import ElegooMars, PrinterState


frontend_dist_directory: str = os.path.abspath("./frontend/dist/")
app = Flask(
    __name__,
    template_folder=frontend_dist_directory,
    static_folder=frontend_dist_directory,
)
# pyre-ignore[8]: incompatible attribute type
app.wsgi_app = WhiteNoise(app.wsgi_app)
# pyre-ignore[16]: undefined attribute
app.wsgi_app.add_files(frontend_dist_directory)

app.config.from_mapping(
    {"DEBUG": True, "CACHE_TYPE": "simple", "CACHE_DEFAULT_TIMEOUT": 300}
)
cache = Cache(app)


@cache.memoize(timeout=0)
def _read_ctb_file(filename: str) -> CTBFile:
    return CTBFile.read(FILES_DIRECTORY / filename)


@app.route("/", methods=["GET"])
def index() -> str:
    return render_template("index.html")


@app.route("/api/print_status", methods=["GET"])
def print_status() -> str:
    with ElegooMars() as elegoo_mars:
        selected_file = elegoo_mars.get_selected_file()
        print_status = elegoo_mars.get_print_status()

        if print_status.state == PrinterState.IDLE:
            progress = 0.0
            print_details = {}
        else:
            ctb_file = _read_ctb_file(selected_file)

            if print_status.current_byte == 0:
                current_layer = 1
            else:
                current_layer = (
                    ctb_file.end_byte_offset_by_layer.index(print_status.current_byte)
                    + 1
                )

            print_details = {
                "current_layer": current_layer,
                "layer_count": ctb_file.layer_count,
                "print_time_secs": ctb_file.print_time_secs,
            }

            progress = (
                100.0
                * none_throws(print_status.current_byte)
                / none_throws(print_status.total_bytes)
            )

        return jsonify(
            {
                "state": print_status.state.value,
                "selected_file": selected_file,
                "progress": progress,
                **print_details,
            }
        )


@app.route("/api/list_files", methods=["GET"])
def list_files() -> str:
    filename_list = os.listdir(FILES_DIRECTORY)
    files = []
    for filename in filename_list:
        ctb_file = _read_ctb_file(filename)
        files.append(
            {
                "filename": filename,
                "print_time_secs": ctb_file.print_time_secs,
            }
        )
    return jsonify(
        {
            "files": files,
        }
    )


class PrinterCommand(Enum):
    START_PRINT = "start_print"
    PAUSE_PRINT = "pause_print"
    RESUME_PRINT = "resume_print"
    CANCEL_PRINT = "cancel_print"
    REBOOT = "reboot"


@app.route("/api/printer/command/<command>", methods=["POST"])
def printer_command(command: str) -> str:
    printer_command = PrinterCommand(command)
    with ElegooMars() as elegoo_mars:
        if printer_command == PrinterCommand.START_PRINT:
            # TODO: validate filename before sending it to the printer
            filename = str(request.args.get("filename"))
            elegoo_mars.start_printing(filename)
        elif printer_command == PrinterCommand.PAUSE_PRINT:
            elegoo_mars.pause_printing()
        elif printer_command == PrinterCommand.RESUME_PRINT:
            elegoo_mars.resume_printing()
        elif printer_command == PrinterCommand.CANCEL_PRINT:
            elegoo_mars.stop_printing()
        elif printer_command == PrinterCommand.REBOOT:
            elegoo_mars.reboot()
        return jsonify({"success": True})


def main() -> None:
    logger = logging.getLogger("waitress")
    logger.setLevel(logging.INFO)
    serve(app, host="0.0.0.0", port=5000)
