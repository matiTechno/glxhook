#include <dlfcn.h>

#include "elfhacks.h"

#include <GL/glx.h>

#include <iostream>
#include <string>

void swapHook()
{
    std::cout << "glXSwapBuffers hook" << std::endl;
}

void clearHook()
{
    std::cout << "glClear hook" << std::endl;
}

void glClear(GLbitfield mask)
{
    using F = void(*)(GLbitfield);

    static F handle = nullptr;

    if(!handle)
        handle = (F)glXGetProcAddress((const GLubyte*)"my glClear");

    clearHook();

    handle(mask);
}

void glXSwapBuffers(Display* dpy, GLXDrawable drawable)
{
    using F = void(*)(Display*, GLXDrawable);

    static F handle = nullptr;

    if(!handle)
        handle = (F)dlsym(RTLD_NEXT, "my glXSwapBuffers");

    swapHook();

    handle(dpy, drawable);
}

using Proc = void(*)();

Proc glXGetProcAddress(const GLubyte* procName)
{
    std::cout << "glXGetProcAddress hook" << std::endl;

    using F = void*(*)(const GLubyte*);

    static F handle = nullptr;

    if(!handle)
        handle = (F)dlsym(RTLD_NEXT, "my glXGetProcAddress");

    std::string name((const char*)procName);

    if(name == "glClear")
        return (Proc)glClear;

    if(name == "my glClear")
        return (Proc)handle((const GLubyte*)"glClear");

    return (Proc)handle(procName);
}

void* dlsym(void* argHandle, const char* symbol)
{
    using F = void*(*)(void*, const char*);

    static F handle = nullptr;

    if(!handle)
    {
        eh_obj_t libdl;

        if(eh_find_obj(&libdl, "*/libdl.so*"))
        {
            std::cout << "Couldn't find libdl!" << std::endl;
            exit(EXIT_FAILURE);
        }

        if(eh_find_sym(&libdl, "dlsym", (void**)&handle))
        {
            std::cout << "Couldn't find dlsym in libdl!" << std::endl;
            eh_destroy_obj(&libdl);
            exit(EXIT_FAILURE);
        }
        
        eh_destroy_obj(&libdl);
    }
    
    std::string name(symbol);
    
    if(name == "glXGetProcAddress")
        return (void*)glXGetProcAddress;

    if(name == "my glXGetProcAddress")
        return (void*)handle(argHandle, "glXGetProcAddress");

    if(name == "glXSwapBuffers")
        return (void*)glXSwapBuffers;

    if(name == "my glXSwapBuffers")
        return (void*)handle(argHandle, "glXSwapBuffers");
    
    return (void*)handle(argHandle, symbol);
}
