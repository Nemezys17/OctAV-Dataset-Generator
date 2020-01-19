# coding: utf-8

from typing import List


class SyscallParsingException(Exception):
    pass


class Syscall(object):

    """
    A `Syscall` object is basically a parsed line of strace
    """

    __slots__ = ("name", "raw_parameters", "parameters", "return_value")

    def __init__(self, strace_syscall_line: str):
        # It could either mean the program is waiting for some stdin input or its running too fast for strace
        if "<unfinished ...>" in strace_syscall_line:
            raise SyscallParsingException("unfinished syscall")

        end_syscall_name = strace_syscall_line.find("(")

        if end_syscall_name == -1:  # Skip debug output lines
            raise SyscallParsingException("debug output detected")

        begin_return_value = strace_syscall_line.rfind("=")

        # return value of syscall not found
        if begin_return_value == -1:
            raise SyscallParsingException("return value of syscall not found")

        begin_return_value += 2
        end_return_value = strace_syscall_line.find(" ", begin_return_value)

        begin_parameter = end_syscall_name + 1
        end_parameter = strace_syscall_line.rfind(")", 0, begin_return_value)

        if end_parameter == -1:
            raise SyscallParsingException("parameter parsing error")

        self.name = strace_syscall_line[:end_syscall_name]
        self.raw_parameters = strace_syscall_line[begin_parameter:end_parameter]

        # FIXME: will not work with a string containing ", "
        self.parameters = self.raw_parameters.split(", ")

        if end_return_value == -1:
            self.return_value = strace_syscall_line[begin_return_value:]
        else:
            self.return_value = strace_syscall_line[begin_return_value:end_return_value]

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"{self.name}({', '.join(self.parameters)}) = {self.return_value}"


class Flow(List[Syscall]):

    def __init__(self, command_line, pid, syscalls: List[Syscall] = None):
        super().__init__()
        self.command_line = command_line
        self.pid = pid

        if syscalls:
            for syscall in syscalls:
                self.append(syscall)

    def __str__(self):
        return ",".join([syscall.name for syscall in self])

    def __repr__(self):
        return f"[pid {self.pid}] " + str(self)

    def __eq__(self, other):

        if not isinstance(other, Flow):
            raise NotImplemented

        for syscall, other_syscall in zip(self, other):
            if syscall.name != other_syscall.name:
                return False

        return True

    def __hash__(self):
        return hash(str(self))


class Execution(List[Flow]):

    def __init__(self, command_line, flows, is_malware):
        super().__init__()

        if isinstance(command_line, str):
            self.command_line = command_line
        elif isinstance(command_line, list):
            self.command_line = " ".join(command_line)
        else:
            raise NotImplemented

        self.is_malware = is_malware

        for flow in flows:
            self.append(flow)
