# ui/animations.py
import sys
import time
import threading


class LoadingAnimation:
    """
    Context-manager based loading animation
    Usage:
        with LoadingAnimation("Initializing..."):
            do_work()
    """

    def __init__(self, message="Loading"):
        self.message = message
        self.running = False
        self.thread = None
        self.spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def _animate(self):
        i = 0
        while self.running:
            sys.stdout.write(
                f"\r{self.message} {self.spinner[i % len(self.spinner)]}"
            )
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1

    def __enter__(self):
        self.running = True
        self.thread = threading.Thread(target=self._animate)
        self.thread.daemon = True
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.running = False
        if self.thread:
            self.thread.join()
        sys.stdout.write("\r" + " " * (len(self.message) + 4) + "\r")
        sys.stdout.flush()
