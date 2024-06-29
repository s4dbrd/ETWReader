#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

void ListAllProviders() {
    ULONG bufferSize = 0;
    ULONG status = EnumerateTraceGuidsEx(TraceGuidQueryList, NULL, 0, NULL, 0, &bufferSize);
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        std::wcerr << L"Failed to query buffer size for providers: " << status << std::endl;
        return;
    }

    std::vector<BYTE> buffer(bufferSize);
    status = EnumerateTraceGuidsEx(TraceGuidQueryList, NULL, 0, buffer.data(), bufferSize, &bufferSize);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to enumerate providers: " << status << std::endl;
        return;
    }

    ULONG numberOfGuids = bufferSize / sizeof(GUID);
    GUID* guidArray = reinterpret_cast<GUID*>(buffer.data());

    for (ULONG i = 0; i < numberOfGuids; i++) {
        std::wcout << std::hex << std::setw(8) << std::setfill(L'0') << guidArray[i].Data1 << L"-"
            << std::setw(4) << guidArray[i].Data2 << L"-"
            << std::setw(4) << guidArray[i].Data3 << L"-";
        for (int j = 0; j < 2; ++j) {
            std::wcout << std::setw(2) << static_cast<int>(guidArray[i].Data4[j]);
        }
        std::wcout << L"-";
        for (int j = 2; j < 8; ++j) {
            std::wcout << std::setw(2) << static_cast<int>(guidArray[i].Data4[j]);
        }
        std::wcout << std::dec << std::endl;
    }
}

void EnableProvider(TRACEHANDLE sessionHandle, const GUID& providerGuid) {
    ULONG status = EnableTraceEx2(
        sessionHandle,
        &providerGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        NULL
    );

    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to enable provider: " << status << std::endl;
    }
}

void DeleteTraceSession(const std::wstring& sessionName) {
    EVENT_TRACE_PROPERTIES* sessionProperties = nullptr;
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (sessionName.size() + 1) * sizeof(wchar_t);

    sessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    ZeroMemory(sessionProperties, bufferSize);

    sessionProperties->Wnode.BufferSize = bufferSize;
    sessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = ControlTrace(NULL, sessionName.c_str(), sessionProperties, EVENT_TRACE_CONTROL_STOP);
    if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND) {
        std::wcerr << L"Failed to delete trace session: " << status << std::endl;
    }
    else {
        std::wcout << L"Trace session deleted successfully." << std::endl;
    }

    free(sessionProperties);
}

void PrintProperties(PEVENT_RECORD eventRecord) {
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO eventInfo = NULL;
    TDHSTATUS status = TdhGetEventInformation(eventRecord, 0, NULL, eventInfo, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        eventInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        status = TdhGetEventInformation(eventRecord, 0, NULL, eventInfo, &bufferSize);
    }
    if (ERROR_SUCCESS != status) {
        if (eventInfo) {
            free(eventInfo);
        }
        return;
    }

    std::wcout << L"Event ID: " << eventRecord->EventHeader.EventDescriptor.Id << std::endl;
    std::wcout << L"Provider Name: " << (eventInfo->ProviderNameOffset ? (PCWSTR)((PBYTE)eventInfo + eventInfo->ProviderNameOffset) : L"Unknown") << std::endl;

    for (DWORD i = 0; i < eventInfo->TopLevelPropertyCount; i++) {
        PROPERTY_DATA_DESCRIPTOR dataDescriptor;
        dataDescriptor.PropertyName = (ULONGLONG)((PBYTE)eventInfo + eventInfo->EventPropertyInfoArray[i].NameOffset);
        dataDescriptor.ArrayIndex = ULONG_MAX;

        bufferSize = 0;
        status = TdhGetPropertySize(eventRecord, 0, NULL, 1, &dataDescriptor, &bufferSize);
        if (status != ERROR_SUCCESS) {
            continue;
        }

        std::vector<BYTE> propertyBuffer(bufferSize);
        status = TdhGetProperty(eventRecord, 0, NULL, 1, &dataDescriptor, bufferSize, propertyBuffer.data());
        if (status != ERROR_SUCCESS) {
            continue;
        }

        std::wcout << reinterpret_cast<PCWSTR>((PBYTE)eventInfo + eventInfo->EventPropertyInfoArray[i].NameOffset) << L": ";

        switch (eventInfo->EventPropertyInfoArray[i].nonStructType.InType) {
        case TDH_INTYPE_UINT32:
            std::wcout << *reinterpret_cast<PULONG>(propertyBuffer.data()) << std::endl;
            break;
        case TDH_INTYPE_UINT64:
            std::wcout << *reinterpret_cast<PULONG64>(propertyBuffer.data()) << std::endl;
            break;
        case TDH_INTYPE_UNICODESTRING:
            std::wcout << reinterpret_cast<PCWSTR>(propertyBuffer.data()) << std::endl;
            break;
        case TDH_INTYPE_ANSISTRING:
            std::wcout << reinterpret_cast<PCSTR>(propertyBuffer.data()) << std::endl;
            break;
        case TDH_INTYPE_POINTER:
            std::wcout << reinterpret_cast<PVOID>(propertyBuffer.data()) << std::endl;
            break;
        case TDH_INTYPE_FILETIME:
        {
            FILETIME fileTime = *reinterpret_cast<PFILETIME>(propertyBuffer.data());
            SYSTEMTIME stUTC, stLocal;
            FileTimeToSystemTime(&fileTime, &stUTC);
            SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
            std::wcout << stLocal.wYear << L"/" << stLocal.wMonth << L"/" << stLocal.wDay << L" "
                << stLocal.wHour << L":" << stLocal.wMinute << L":" << stLocal.wSecond << std::endl;
            break;
        }
        default:
            std::wcout << L"(Unknown type)" << std::endl;
            break;
        }
    }
    if (eventInfo) {
        free(eventInfo);
    }
}

void WINAPI EventRecordCallback(PEVENT_RECORD eventRecord) {
    std::wstring eventName;

    // This is exclusively for Microsoft-Windows-Kernel-Process provider, change the Event IDs for other providers
    switch (eventRecord->EventHeader.EventDescriptor.Id) {
    case 1:  // Process Start
        eventName = L"Start Process";
        break;
    case 2:  // Process Stop
        eventName = L"Stop Process";
        break;
    case 3:  // Thread Start
        eventName = L"Start Thread";
        break;
    case 4:  // Thread Stop
        eventName = L"Stop Thread";
        break;
    case 5:  // Image Load
        eventName = L"Load Image";
        break;
    case 6:  // Image Unload
        eventName = L"Unload Image";
        break;
    default:
        // Ignore other events
        return;
    }

    std::wcout << L"\nEvent Name: " << eventName << std::endl;
    PrintProperties(eventRecord);
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc > 1 && wcscmp(argv[1], L"--list") == 0) {
        ListAllProviders();
        return 0;
    }

    if (argc < 3) {
        std::wcerr << L"Usage: " << argv[0] << L" <session_name> <provider_guid> [-d]" << std::endl;
        return 1;
    }

    std::wstring sessionName = argv[1];
    GUID providerGuid;
    if (CLSIDFromString(argv[2], &providerGuid) != NOERROR) {
        std::wcerr << L"Invalid provider GUID format." << std::endl;
        return 1;
    }

    bool deleteSession = (argc == 4 && wcscmp(argv[3], L"-d") == 0);

    if (deleteSession) {
        DeleteTraceSession(sessionName);
        return 0;
    }

    TRACEHANDLE sessionHandle = 0;
    EVENT_TRACE_PROPERTIES* sessionProperties = nullptr;
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (sessionName.size() + 1) * sizeof(wchar_t);

    sessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    ZeroMemory(sessionProperties, bufferSize);

    sessionProperties->Wnode.BufferSize = bufferSize;
    sessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    sessionProperties->Wnode.ClientContext = 1;  // QPC clock resolution
    sessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    sessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTrace(&sessionHandle, sessionName.c_str(), sessionProperties);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to start trace: " << status << std::endl;
        free(sessionProperties);
        return 1;
    }

    EnableProvider(sessionHandle, providerGuid);

    wchar_t* sessionNameBuffer = new wchar_t[sessionName.size() + 1];
    wcscpy_s(sessionNameBuffer, sessionName.size() + 1, sessionName.c_str());

    EVENT_TRACE_LOGFILE traceLogfile;
    ZeroMemory(&traceLogfile, sizeof(EVENT_TRACE_LOGFILE));
    traceLogfile.LoggerName = sessionNameBuffer;
    traceLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    traceLogfile.EventRecordCallback = EventRecordCallback;

    TRACEHANDLE traceHandle = OpenTrace(&traceLogfile);
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        std::wcerr << L"Failed to open trace: " << GetLastError() << std::endl;
        delete[] sessionNameBuffer;
        free(sessionProperties);
        return 1;
    }

    status = ProcessTrace(&traceHandle, 1, 0, 0);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to process trace: " << status << std::endl;
    }

    status = ControlTrace(sessionHandle, sessionName.c_str(), sessionProperties, EVENT_TRACE_CONTROL_STOP);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to stop trace: " << status << std::endl;
    }

    CloseTrace(traceHandle);
    delete[] sessionNameBuffer;
    free(sessionProperties);
    return 0;
}
