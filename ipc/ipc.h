#ifndef IPC_H
#define IPC_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QMap>
#include <QSet>
#include <QList>
#include <functional>

#include "../client/utilities.h"

#define IPC_SERVICE_URL "local:AmneziaVpnIpcInterface"

namespace amnezia {

enum PermittedProcess {
    Invalid,
    OpenVPN,
    Wireguard,
    Tun2Socks,
    CertUtil
};

inline QString permittedProcessPath(PermittedProcess pid)
{
    switch (pid) {
        case PermittedProcess::OpenVPN:
            return Utils::openVpnExecPath();
        case PermittedProcess::Wireguard:
            return Utils::wireguardExecPath();
        case PermittedProcess::CertUtil:
            return Utils::certUtilPath();
        case PermittedProcess::Tun2Socks:
            return Utils::tun2socksPath();
        default:
            return "";
    }
}


inline QString getIpcServiceUrl() {
#ifdef Q_OS_WIN
    return IPC_SERVICE_URL;
#else
    return QString("/tmp/%1").arg(IPC_SERVICE_URL);
#endif
}

inline QString getIpcProcessUrl(int pid) {
#ifdef Q_OS_WIN
    return QString("%1_%2").arg(IPC_SERVICE_URL).arg(pid);
#else
    return QString("/tmp/%1_%2").arg(IPC_SERVICE_URL).arg(pid);
#endif
}

inline QStringList sanitizeArguments(PermittedProcess proc, const QStringList &args) {
    using Validator = std::function<bool(const QString&)>;
    QMap<QString, Validator> namedArgs;
    QList<Validator> positionalArgs;

    switch (proc) {
    case Tun2Socks:
        namedArgs["-device"] = [](const QString& v) { return v.startsWith("tun://"); };
        namedArgs["-proxy"] = [](const QString& v) { return v.startsWith("socks5://"); };
        break;
    default:
        // AMNEZIA-2 fix: this was `return args;` unconditionally (a `//FIXME`),
        // letting a caller of the unauthenticated IPC service (see
        // localserver.cpp -- no peer-credential check on connect) inject any
        // OpenVPN flag, e.g. `--up "/bin/sh -c ..."` + `--script-security 2`,
        // for root to execute. Block the specific flags that turn "extra
        // argument" into "run an attacker command" -- everything else (the
        // config path, management host/port, etc.) still passes through
        // unchanged, same as before.
        static const QSet<QString> dangerous = {
            "--up", "--down", "--route-up", "--route-pre-down", "--ipchange",
            "--learn-address", "--client-connect", "--client-disconnect",
            "--auth-user-pass-verify", "--tls-verify", "--plugin",
            "--script-security",
        };
        for (const auto &a : args) {
            if (dangerous.contains(a))
                return {};
        }
        return args;
    }

    QStringList sanitized;

    for (int i = 0, pos = 0; i < args.size(); i++) {
        const auto& key = args[i];

        if (const auto found = namedArgs.find(key); found != namedArgs.end()) {
            const auto validator = found.value();

            if (validator) {
                if (i + 1 < args.size()) {
                    const auto& value = args[i+1];
                    if (validator(value)) {
                        sanitized << key << value;
                        i++;
                    }
                }
            } else {
                sanitized << key;
            }
        } else if (pos < positionalArgs.size()) {
            if (const auto validator = positionalArgs[pos]; validator && validator(key)) {
                sanitized << key;
                pos++;
            }
        }
    }

    return sanitized;
}

} // namespace amnezia

#endif // IPC_H
