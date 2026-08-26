#include <iostream>
#include <fstream>
#include <stdio.h>
#include "js.h"
extern "C" {
    #include <quickjs-libc.h>
}

struct JS::PersistentState {
    JSRuntime* rt = nullptr;
    JSContext* ctx = nullptr;
    JSValue runner = JS_UNDEFINED;
    size_t runCount = 0;
};

JS::JS(void) :
    memoryLimit(0) {
}

JS::~JS(void) {
    ResetPersistentState();
}

void JS::ResetPersistentState(void) {
    if ( persistentState == nullptr ) {
        return;
    }

    if ( persistentState->ctx != nullptr ) {
        JS_FreeValue(persistentState->ctx, persistentState->runner);
        JS_FreeContext(persistentState->ctx);
    }
    if ( persistentState->rt != nullptr ) {
        js_std_free_handlers(persistentState->rt);
        JS_FreeRuntime(persistentState->rt);
    }

    persistentState.reset();
}

void JS::SetBytecode(const std::vector<char>& bytecode) {
    SetBytecode(std::vector<uint8_t>(
                (uint8_t*)bytecode.data(),
                (uint8_t*)(bytecode.data() + bytecode.size())));
}
        
void JS::SetBytecode(const std::vector<uint8_t>& bytecode) {
    ResetPersistentState();
    this->bytecode = bytecode;
}

void JS::SetMemoryLimit(const size_t limit) {
    ResetPersistentState();
    memoryLimit = limit;
}

void JS::SetEntrypoint(const std::string& name) {
    ResetPersistentState();
    entrypoint = name;
}

std::vector<char> JS::LoadFile(const std::string& fn) {
    std::vector<char> buffer;
    std::ifstream file(fn, std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    if ( size <= 0 ) {
        throw std::runtime_error("LoadFile: Load error");
    }
    file.seekg(0, std::ios::beg);

    buffer.resize(size+1);
    if (!file.read(buffer.data(), size)) {
        throw std::runtime_error("LoadFile: Read error");
    }
    buffer[size] = 0x00;

    return buffer;
}

std::vector<uint8_t> JS::CompileJavascript(const std::string& javascriptFilename) {
    std::vector<char> buffer;

    try {
        buffer = LoadFile(javascriptFilename);
    } catch (const std::exception&) {
        std::cout << "Cannot read JavaScript file" << std::endl;
        exit(1);
    }

    {
        std::vector<uint8_t> ret;
        JSRuntime* rt = JS_NewRuntime();
        JSContext* ctx = JS_NewContext(rt);

        JS_AddIntrinsicEval(ctx);
        JS_AddIntrinsicRegExpCompiler(ctx);

        JSValue obj;
        
        /* Parse */
        {
            obj = JS_Eval(
                    ctx,
                    buffer.data(),
                    buffer.size() - 1,
                    javascriptFilename.c_str(),
                    JS_EVAL_FLAG_COMPILE_ONLY | JS_EVAL_TYPE_GLOBAL | JS_EVAL_TYPE_MODULE);
            if (JS_IsException(obj)) {
                goto err_compile;
            }
        }

        /* To bytecode */
        {
            size_t out_buf_len;
            uint8_t* out_buf = JS_WriteObject(ctx, &out_buf_len, obj, JS_WRITE_OBJ_BYTECODE);
            if ( !out_buf ) {
                goto err_compile;
            }

            ret = std::vector<uint8_t>(out_buf, out_buf + out_buf_len);

            js_free(ctx, out_buf);
        }

        JS_FreeValue(ctx, obj);

        JS_FreeContext(ctx);
        JS_FreeRuntime(rt);

        return ret;

err_compile:
        js_std_dump_error(ctx);
        std::cout << "Cannot compile JavaScript file" << std::endl;
        exit(1);
    }
}

std::optional<std::string> JS::Run(const std::string& data) {
    return Run(data.data(), data.size(), true);
}

std::optional<std::string> JS::Run(const void* data, const size_t size, const bool asString) {
    if ( entrypoint.empty() == false && asString == true ) {
        return RunPersistent(data, size);
    }

    return RunFresh(data, size, asString);
}

bool JS::InitializePersistentState(void) {
    if ( persistentState != nullptr ) {
        return true;
    }

    if ( bytecode.empty() ) {
        std::cout << "No bytecode defined" << std::endl;
        exit(1);
    }

    auto state = std::make_unique<PersistentState>();
    state->rt = JS_NewRuntime();
    if ( state->rt == nullptr ) {
        return false;
    }
    js_std_init_handlers(state->rt);

    state->ctx = JS_NewContext(state->rt);
    if ( state->ctx == nullptr ) {
        js_std_free_handlers(state->rt);
        JS_FreeRuntime(state->rt);
        return false;
    }

    if ( memoryLimit ) {
        /* noret */ JS_SetMemoryLimit(state->rt, memoryLimit);
    }
    /* noret */ JS_SetGCThreshold(state->rt, -1);
    /* noret */ js_std_add_helpers(state->ctx, 0, nullptr);

    /* The persistent harness declares its entrypoint while the bundle loads. */
    /* noret */ js_std_eval_binary(state->ctx, bytecode.data(), bytecode.size(), 0);
    /* noret */ js_std_loop(state->ctx);

    const auto global = JS_GetGlobalObject(state->ctx);
    state->runner = JS_GetPropertyStr(state->ctx, global, entrypoint.c_str());
    JS_FreeValue(state->ctx, global);

    if ( JS_IsException(state->runner) || JS_IsFunction(state->ctx, state->runner) == false ) {
        if ( JS_IsException(state->runner) ) {
            js_std_dump_error(state->ctx);
        }
        JS_FreeValue(state->ctx, state->runner);
        JS_FreeContext(state->ctx);
        js_std_free_handlers(state->rt);
        JS_FreeRuntime(state->rt);
        return false;
    }

    persistentState = std::move(state);
    return true;
}

std::optional<std::string> JS::RunPersistent(const void* data, const size_t size) {
    std::optional<std::string> ret = std::nullopt;

    if ( InitializePersistentState() == false ) {
        return ret;
    }

    auto input = JS_NewStringLen(
            persistentState->ctx,
            static_cast<const char*>(data),
            size);
    if ( JS_IsException(input) ) {
        js_std_dump_error(persistentState->ctx);
        ResetPersistentState();
        return ret;
    }

    const auto result = JS_Call(
            persistentState->ctx,
            persistentState->runner,
            JS_UNDEFINED,
            1,
            &input);
    JS_FreeValue(persistentState->ctx, input);

    if ( JS_IsException(result) ) {
        js_std_dump_error(persistentState->ctx);
        JS_FreeValue(persistentState->ctx, result);
        ResetPersistentState();
        return ret;
    }

    if ( JS_IsString(result) ) {
        size_t outputSize = 0;
        const char* output = JS_ToCStringLen(persistentState->ctx, &outputSize, result);
        if ( output != nullptr ) {
            ret = std::string(output, outputSize);
            JS_FreeCString(persistentState->ctx, output);
        } else {
            JS_FreeValue(persistentState->ctx, result);
            js_std_dump_error(persistentState->ctx);
            ResetPersistentState();
            return ret;
        }
    }
    JS_FreeValue(persistentState->ctx, result);

    persistentState->runCount++;
    if ( (persistentState->runCount % 1024) == 0 ) {
        JS_RunGC(persistentState->rt);
    }

    return ret;
}

std::optional<std::vector<uint8_t>> JS::RunByteArrays(
        const std::string& functionName,
        const std::vector<std::string>& stringArguments,
        const std::vector<std::pair<const uint8_t*, size_t>>& byteArrays) {
    std::optional<std::vector<uint8_t>> ret = std::nullopt;

    if ( entrypoint.empty() || InitializePersistentState() == false ) {
        return ret;
    }

    auto global = JS_GetGlobalObject(persistentState->ctx);
    auto runner = JS_GetPropertyStr(persistentState->ctx, global, functionName.c_str());
    JS_FreeValue(persistentState->ctx, global);
    if ( JS_IsException(runner) || JS_IsFunction(persistentState->ctx, runner) == false ) {
        if ( JS_IsException(runner) ) {
            js_std_dump_error(persistentState->ctx);
        }
        JS_FreeValue(persistentState->ctx, runner);
        ResetPersistentState();
        return ret;
    }

    std::vector<JSValue> arguments;
    arguments.reserve(stringArguments.size() + 1);
    for (const auto& stringArgument : stringArguments) {
        auto argument = JS_NewStringLen(
                persistentState->ctx,
                stringArgument.data(),
                stringArgument.size());
        if ( JS_IsException(argument) ) {
            js_std_dump_error(persistentState->ctx);
            for (const auto& value : arguments) {
                JS_FreeValue(persistentState->ctx, value);
            }
            JS_FreeValue(persistentState->ctx, runner);
            ResetPersistentState();
            return ret;
        }
        arguments.push_back(argument);
    }

    auto array = JS_NewArray(persistentState->ctx);
    if ( JS_IsException(array) ) {
        js_std_dump_error(persistentState->ctx);
        for (const auto& value : arguments) {
            JS_FreeValue(persistentState->ctx, value);
        }
        JS_FreeValue(persistentState->ctx, runner);
        ResetPersistentState();
        return ret;
    }

    for (size_t i = 0; i < byteArrays.size(); i++) {
        auto buffer = JS_NewArrayBuffer(
                persistentState->ctx,
                const_cast<uint8_t*>(byteArrays[i].first),
                byteArrays[i].second,
                nullptr,
                nullptr,
                false);
        if ( JS_IsException(buffer) ||
                JS_SetPropertyUint32(persistentState->ctx, array, i, buffer) < 0 ) {
            js_std_dump_error(persistentState->ctx);
            JS_FreeValue(persistentState->ctx, array);
            for (const auto& value : arguments) {
                JS_FreeValue(persistentState->ctx, value);
            }
            JS_FreeValue(persistentState->ctx, runner);
            ResetPersistentState();
            return ret;
        }
    }
    arguments.push_back(array);

    auto result = JS_Call(
            persistentState->ctx,
            runner,
            JS_UNDEFINED,
            arguments.size(),
            arguments.data());
    for (const auto& value : arguments) {
        JS_FreeValue(persistentState->ctx, value);
    }
    JS_FreeValue(persistentState->ctx, runner);

    if ( JS_IsException(result) ) {
        js_std_dump_error(persistentState->ctx);
        JS_FreeValue(persistentState->ctx, result);
        ResetPersistentState();
        return ret;
    }

    size_t outputOffset = 0;
    size_t outputLength = 0;
    size_t bytesPerElement = 0;
    auto outputBuffer = JS_GetTypedArrayBuffer(
            persistentState->ctx,
            result,
            &outputOffset,
            &outputLength,
            &bytesPerElement);
    if ( JS_IsException(outputBuffer) || bytesPerElement != 1 ) {
        JS_FreeValue(persistentState->ctx, outputBuffer);
        JS_FreeValue(persistentState->ctx, result);
        js_std_dump_error(persistentState->ctx);
        ResetPersistentState();
        return ret;
    }

    size_t outputBufferSize = 0;
    const auto output = JS_GetArrayBuffer(
            persistentState->ctx,
            &outputBufferSize,
            outputBuffer);
    if ( outputOffset > outputBufferSize ||
            outputLength > outputBufferSize - outputOffset ||
            (output == nullptr && outputLength != 0) ) {
        JS_FreeValue(persistentState->ctx, outputBuffer);
        JS_FreeValue(persistentState->ctx, result);
        js_std_dump_error(persistentState->ctx);
        ResetPersistentState();
        return ret;
    }

    if ( outputLength == 0 ) {
        ret = std::vector<uint8_t>();
    } else {
        ret = std::vector<uint8_t>(
                output + outputOffset,
                output + outputOffset + outputLength);
    }
    JS_FreeValue(persistentState->ctx, outputBuffer);
    JS_FreeValue(persistentState->ctx, result);

    persistentState->runCount++;
    if ( (persistentState->runCount % 1024) == 0 ) {
        JS_RunGC(persistentState->rt);
    }

    return ret;
}

std::optional<std::string> JS::RunFresh(const void* data, const size_t size, const bool asString) {
    std::optional<std::string> ret = std::nullopt;

    JSRuntime* rt = nullptr;
    JSContext* ctx = nullptr;

    if ( bytecode.empty() ) {
        std::cout << "No bytecode defined" << std::endl;
        exit(1);
    }

    /* Instantiate */
    {
        rt = JS_NewRuntime();
        js_std_init_handlers(rt);
        ctx = JS_NewContext(rt);
    }

    /* Configure */
    {
        if ( memoryLimit ) {
            /* noret */ JS_SetMemoryLimit(rt, memoryLimit);
        }
        /* noret */ JS_SetGCThreshold(rt, -1);
        /* noret */ js_std_add_helpers(ctx, 0, nullptr);
    }

    /* Specify input */
    {
        const std::string scriptHeader =
            asString == false ?
                "var FuzzerOutput; var FuzzerInput = new Uint8Array([" :
                "var FuzzerOutput; var FuzzerInput = \"";

        std::string scriptBody;
        const std::string scriptFooter = asString == false ? "]);" : "\";";

        for (size_t i = 0; i < size; i++) {
            if ( asString == false ) {
                scriptBody += std::to_string(((const uint8_t*)data)[i]);
                if ( i + 1 != size ) {
                    scriptBody += ",";
                }
            } else {
                char hex[16];
                sprintf(hex, "\\x%02X", ((const uint8_t*)data)[i]);
                scriptBody += hex;
            }
        }

        const std::string script = scriptHeader + scriptBody + scriptFooter;
        JSValue val = JS_Eval(ctx, script.data(), script.size(), "<none>", JS_EVAL_TYPE_GLOBAL);
        if (JS_IsException(val)) {
            js_std_dump_error(ctx);
            exit(1);
        }
        JS_FreeValue(ctx, val);
    }

    /* Run */
    {
        /* noret */ js_std_eval_binary(ctx, bytecode.data(), bytecode.size(), 0);
        /* noret */ js_std_loop(ctx);


        /* Extract output */
        {
            auto global = JS_GetGlobalObject(ctx);
            auto val = JS_GetPropertyStr(ctx, global, "FuzzerOutput");
            if (JS_IsException(val)) {
                js_std_dump_error(ctx);
                exit(1);
            }
            if (JS_IsString(val)) {
                size_t outputSize = 0;
                const char* output = JS_ToCStringLen(ctx, &outputSize, val);
                if (output != nullptr) {
                    ret = std::string(output, outputSize);
                    JS_FreeCString(ctx, output);
                }
            }
            JS_FreeValue(ctx, val);
            JS_FreeValue(ctx, global);
        }
    }

    /* Free */
    {
        /* noret */ JS_FreeContext(ctx);
        /* noret */ js_std_free_handlers(rt);
        /* noret */ JS_FreeRuntime(rt);
    }

    return ret;
}
