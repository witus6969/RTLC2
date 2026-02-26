// task.cpp - Task utility functions
// Additional task processing helpers

#include "agent.h"
#include "crypto.h"
#include <cstring>

namespace rtlc2 {

// Task type name lookup
const char* TaskTypeName(TaskType type) {
    switch (type) {
        case TaskType::Shell:       return "shell";
        case TaskType::Upload:      return "upload";
        case TaskType::Download:    return "download";
        case TaskType::Sleep:       return "sleep";
        case TaskType::Exit:        return "exit";
        case TaskType::Inject:      return "inject";
        case TaskType::BOF:         return "bof";
        case TaskType::Assembly:    return "assembly";
        case TaskType::Screenshot:  return "screenshot";
        case TaskType::Keylog:      return "keylog";
        case TaskType::PS:          return "ps";
        case TaskType::LS:          return "ls";
        case TaskType::CD:          return "cd";
        case TaskType::PWD:         return "pwd";
        case TaskType::Whoami:      return "whoami";
        case TaskType::IPConfig:    return "ipconfig";
        case TaskType::HashDump:    return "hashdump";
        case TaskType::Token:       return "token";
        case TaskType::Pivot:       return "pivot";
        case TaskType::PortScan:    return "portscan";
        case TaskType::Socks:       return "socks";
        case TaskType::SelfDestruct: return "selfdestruct";
        case TaskType::Module:      return "module";
        case TaskType::Clipboard:   return "clipboard";
        case TaskType::RegWrite:    return "regwrite";
        case TaskType::ServiceCtl:  return "servicectl";
        case TaskType::Jobs:        return "jobs";
        case TaskType::Persist:     return "persist";
        case TaskType::Unpersist:   return "unpersist";
        case TaskType::PrivEsc:     return "privesc";
        case TaskType::FileCopy:    return "filecopy";
        case TaskType::FileMove:    return "filemove";
        case TaskType::FileDelete:  return "filedelete";
        case TaskType::MkDir:       return "mkdir";
        case TaskType::RegQuery:    return "regquery";
        case TaskType::EnvVar:      return "envvar";
        case TaskType::RPortFwd:    return "rportfwd";
        case TaskType::RunAs:       return "runas";
        case TaskType::PowerShell:  return "powershell";
        case TaskType::LOLBAS:      return "lolbas";
        default:                    return "unknown";
    }
}

} // namespace rtlc2
