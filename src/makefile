# Compiler and flags
CC = cl
CFLAGS = /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS
LDFLAGS = /nologo

# Targets
all: dll_injector.exe stage_zero.exe win_service.exe legit.dll

# DLL Injector executable
dll_injector.exe: dll_injector.c
	$(CC) $(CFLAGS) /Fedll_injector.exe dll_injector.c $(LDFLAGS)

# Stage Zero executable  
stage_zero.exe: stage_zero.c
	$(CC) $(CFLAGS) /Festage_zero.exe stage_zero.c $(LDFLAGS)

# Windows Service executable
win_service.exe: win_service32.c
	$(CC) $(CFLAGS) /Fewin_service32.exe win_service32.c $(LDFLAGS)

# Legit DLL
legit.dll: legit.c
	$(CC) $(CFLAGS) /Felegit.dll /LD legit.c $(LDFLAGS)

# Clean build artifacts
clean:
	del /Q *.exe *.dll *.obj *.lib *.exp 2>nul

# Rebuild everything
rebuild: clean all

# Help target
help:
	@echo Available targets:
	@echo   all              - Build all targets (default)
	@echo   dll_injector.exe - Build DLL injector
	@echo   stage_zero.exe   - Build stage zero loader
	@echo   win_service.exe  - Build Windows service
	@echo   legit.dll        - Build legit DLL
	@echo   clean            - Remove all build artifacts
	@echo   rebuild          - Clean and rebuild everything
	@echo   help             - Show this help message

.PHONY: all clean rebuild help