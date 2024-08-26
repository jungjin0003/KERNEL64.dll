TARGET=KERNEL64.dll
OBJS=kernel64.obj
LIBS=msvcrt.lib ntdll.lib
CFLAGS=/D_NO_CRT_STDIO_INLINE /D_CRT_SECURE_NO_WARNINGS /Od /Ob1 /Z7 /GS-
LDFLAGS=/NODEFAULTLIB:libcmt.lib /NODEFAULTLIB:msvcprt.lib /MANIFEST:NO /DEBUG:FULL /OPT:REF /OPT:ICF /OPT:LBR /DEF:..\src\kernel64.def /OUT:KERNEL64.dll /DLL /MACHINE:X86

PATH=$(PATH);.\utils
DSRC={.\src\}

CC=cl
LD=link

all: run $(TARGET)

$(TARGET): $(OBJS) $(LIBS) GenerateLibFile
	@cd bin
	$(LD) $(LDFLAGS) kernel64.obj ..\src\msvcrt.lib ..\src\ntdll.lib
	@cd ..
	@move bin\KERNEL64.lib .\lib

$(DSRC).c.obj:
	$(CC) $(CFLAGS) /c /Fo:bin\$@ $<

$(LIBS):
	
GenerateLibFile:
!IF !EXISTS(.\src\ntdll.lib)
	@copy C:\Windows\SysWOW64\ntdll.dll .\src
	@.\utils\gendef.exe .\src\ntdll.dll
	@move .\ntdll.def .\src
	@dlltool.exe -k -d .\src\ntdll.def -l .\src\ntdll.lib
	@del .\src\ntdll.dll
!ENDIF

run:
	@mkdir bin
	@mkdir lib

clean:
	rmdir /s /q .\lib
	rmdir /s /q .\bin