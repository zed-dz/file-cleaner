import tempfile
import unittest
from pathlib import Path

from file_cleaner import sniff


class JpegSniffTest(unittest.TestCase):
    def test_motion_photo_requires_end_marker(self):
        jpeg = b"\xff\xd8\xff\xe0" + b"x" * 5_000
        trailer = b"video" * 1_024

        with tempfile.TemporaryDirectory() as directory:
            photo = Path(directory) / "motion.jpg"

            photo.write_bytes(jpeg + trailer)
            reason = sniff(photo, photo.suffix, photo.stat().st_size)
            assert reason == "JPG end missing (file cut short)"

            photo.write_bytes(jpeg + b"\xff\xd9" + trailer)
            assert sniff(photo, photo.suffix, photo.stat().st_size) is None
