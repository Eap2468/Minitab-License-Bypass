# Minitab-License-Bypass

This is a quick little project I did after finding a couple quick quirks about the software while helping out a friend.

Main idea is the license check is like the news article pop ups where they prevent you from reading further but if you just hop in chrome dev tools and remove the div the popup is wrapped in or set its display to none in CSS then you can read on.

Minitab does a similar thing, the entire UI is still active when the license check pops up and all that happens is the main windows get disabled and click events redirect to the license window. Because of this you can do two things super easily.

1) Find the license windows by title, disable and hide it.
2) Prevent the window from being created again.

Although you can just remove the initial popup there's a bunch of UI actions that will trigger it again. Because of this to do a proper bypass where you don't need to disable it every two seconds you can just side load a DLL into the process, do IAT hijacking on CallWindowProcW, and filter for the WM_NCCREATE messages for the window name "Authentication Required". If one of those messages is caught simply return S_OK without doing anything to prevent the popup while allowing the rest of the application flow to go on as normal.

This is a super dirty PoC I made to mess around a bit rather than a polished project.
If you want persistence for this (as in not needing to run the bypass every time you launch the application), some options are writting a launcher so you can use CreateProcess with CREATE_SUSPENDED and load your DLL at startup or there are some registry keys that allow you to run a process before another process starts which can be used to launch the bypass on program start. Whatever way anyone goes is up to them.

## Usage
Compile the PayloadDLL and MinitabBypass Visual Studio projects. Copy PayloadDLL.dll to C:\Windows\Temp\PayloadDLL.dll (change this in the define in MinitabBypass if you want it elsewhere). Launch Minitab, then launch MinitabBypass.exe. At this point it should get rid of the initial license window and prevent any more from popping up during use.

## Versioning
This has been tested on Minitab 22.5.2, I don't plan on back/forward testing it but would imagine it will work across most if not all versions

For building I used the 10.0.26100.0 SDK with debug builds. Its a super simple project so I wouldn't expect issues on other versions or using release builds but in case of weird optimizations breaking this is a known good.

Use this at your own risk, I am not responsible if you get in trouble for use 
