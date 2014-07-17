OAT-Unix-Linux-scripts
======================

Operations Acceptance Testing scripts for:

SunOS/Solaris (including Solaris 11)
Linux
HP-UX

Copyright 2006-2014 Dusan Baljevic

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Perl scripts are a modest attempt to automate basic tasks when
running Operations Acceptance Testing (OAT) for servers.

The script tries to capture most critical information about Unix/Linux 
servers and highlights potential configuration or system problems
at the same time, so it is not a configuration collector alone!

The script has been developed over several hectic days, so errors
(although not planned) might exist. Please use with care.

There are not many comments throught the script and that
is not best practices for writing good code. However,
I view this script as a learning tool for system administrators
too so lack of comments is partially left as an exercise.

My goals were:

A) Simplicity to do basic Operations Acceptance Testing (OAT)
B) Portability;
C) Standard Perl interpreter;
D) Many new features;
E) Support for different volume managers and file system types;
F) No temporary files;
G) No repeated runs of similar commands;
H) Not to replace more comprehensive debugging tools but
provide a quick summary of servers' status;

Like all scripts and programs, this one will continue to change.

I admit the documentation of the code needs to improve!

You can also visit the author's home page for other scripts
and presentations:

http://www.circlingcycle.com.au/Unix-sources/

http://www.circlingcycle.com.au/Unix-and-Linux-presentations/

Dusan Baljevic VK2COT (dusan.baljevic@ieee.org)
