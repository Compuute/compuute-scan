# Fixture: uvx with --from + user-controlled url — should be flagged by L1-038.
import subprocess

def run_tool(user_url, tool_name):
    args = ["--from", user_url, tool_name]
    subprocess.run("uvx", args, check=True)
