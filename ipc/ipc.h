#ifndef IPC_H
#define IPC_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QMap>
#include <QSet>
#include <QPair>
#include <QList>
#include <QFileInfo>
#include <QRegularExpression>
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

// AMNEZIA-2 fix: this used to be `default: return args;` (a `//FIXME`) for every
// process except Tun2Socks -- OpenVPN, Wireguard and CertUtil arguments passed
// through completely unvalidated. Since createPrivilegedProcess() has no caller
// authentication (see service/server/localserver.cpp), any local unprivileged
// process could set PermittedProcess::OpenVPN and pass an arbitrary argument
// vector (e.g. `--up "/bin/sh -c ..."` with `--script-security 2`) for root to
// execute. Every branch below is now an explicit whitelist of exactly the flags
// the real callers pass (grep-verified against this checkout: see
// client/protocols/openvpnprotocol.cpp, ikev2_vpn_protocol_windows.cpp) --
// anything not matched is silently dropped, same as Tun2Socks already did.
//
// This closes arbitrary-flag injection via the IPC layer. It does NOT by
// itself validate the *content* of the file passed via OpenVPN's --config
// (that file is a QTemporaryFile under the OS temp directory, not
// distinguishable from an attacker-planted file by path alone) -- that's the
// separate, already-tracked config-injection surface (AMNEZIA-1) and needs
// either IPC peer-credential verification (so only the legitimate GUI process
// can reach this at all) or server-side .ovpn content validation, neither of
// which this change attempts.
inline QStringList sanitizeArguments(PermittedProcess proc, const QStringList &args) {
    using Validator = std::function<bool(const QString&)>;
    QMap<QString, Validator> namedArgs;         // flag -> validates exactly one following value
    QSet<QString> flagArgs;                     // flag -> takes no value
    QList<Validator> positionalArgs;            // validated in order, no flag
    QMap<QString, QPair<int, Validator>> multiArgs; // flag -> (N following values, each validated)

    switch (proc) {
    case Tun2Socks:
        namedArgs["-device"] = [](const QString& v) { return v.startsWith("tun://"); };
        namedArgs["-proxy"] = [](const QString& v) { return v.startsWith("socks5://"); };
        break;

    case OpenVPN: {
        // Matches exactly: "--config", configPath(), "--management", host,
        // QString::number(port), "--management-client"
        // (client/protocols/openvpnprotocol.cpp). No --up/--down/--plugin/
        // --script-security/etc. can reach argv from here anymore.
        static const QRegularExpression shellMeta(QStringLiteral("[;&|`$()<>\\n\"']"));
        namedArgs["--config"] = [](const QString& v) {
            return !v.isEmpty() && !v.contains(shellMeta) && QFileInfo(v).isFile();
        };
        flagArgs.insert("--management-client");
        static const QRegularExpression safeToken(QStringLiteral("^[A-Za-z0-9.:_-]+$"));
        multiArgs["--management"] = { 2, [](const QString& v) { return !v.isEmpty() && safeToken.match(v).hasMatch(); } };
        break;
    }

    case CertUtil: {
        // Matches exactly: "-f", "-importpfx", "-p", password, filename, "NoExport"
        // (client/protocols/ikev2_vpn_protocol_windows.cpp). The password value is
        // opaque (passed straight to certutil's argv, not a shell) so any non-empty
        // string is accepted for it; what's now enforced is that no *other* flag or
        // extra positional argument can be smuggled in.
        flagArgs.insert("-f");
        flagArgs.insert("-importpfx");
        namedArgs["-p"] = [](const QString& v) { return !v.isEmpty(); };
        positionalArgs.append([](const QString& v) { return !v.isEmpty() && QFileInfo(v).isFile(); });
        positionalArgs.append([](const QString& v) { return v == QLatin1String("NoExport"); });
        break;
    }

    case Wireguard:
    default:
        // No caller in this checkout currently drives Wireguard through
        // createPrivilegedProcess()/setArguments() (grep-confirmed) -- deny by
        // default instead of the previous unconditional passthrough. Add a real
        // whitelist here if/when a caller needs one, following the pattern above.
        return {};
    }

    QStringList sanitized;
    int pos = 0;
    for (int i = 0; i < args.size(); ) {
        const auto& key = args[i];

        if (const auto mfound = multiArgs.find(key); mfound != multiArgs.end()) {
            const int count = mfound.value().first;
            const auto& validator = mfound.value().second;
            bool allOk = (i + count < args.size());
            for (int k = 1; allOk && k <= count; k++) {
                allOk = validator(args[i + k]);
            }
            if (allOk) {
                sanitized << key;
                for (int k = 1; k <= count; k++) sanitized << args[i + k];
                i += count + 1;
            } else {
                i++;
            }
            continue;
        }

        if (flagArgs.contains(key)) {
            sanitized << key;
            i++;
            continue;
        }

        if (const auto found = namedArgs.find(key); found != namedArgs.end()) {
            const auto& validator = found.value();
            if (i + 1 < args.size() && validator(args[i + 1])) {
                sanitized << key << args[i + 1];
                i += 2;
            } else {
                i++;
            }
            continue;
        }

        if (pos < positionalArgs.size()) {
            if (const auto& validator = positionalArgs[pos]; validator && validator(key)) {
                sanitized << key;
                pos++;
            }
        }
        i++;
    }

    return sanitized;
}

} // namespace amnezia

#endif // IPC_H
