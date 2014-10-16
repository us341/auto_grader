auto_grader
===========

An auto grader written in python which can test all defense and attack programs in Repy v2 against each other for whole class and generate results in .csv format

Description
===========
This module takes all defense programs and attack programs in Repy V2 and creates csv file describing test result of every attack program against each defense program. Under the attack program column, it shows 1 if attack was able to compromise security layer and 0 otherwise. Students submitting attack and defense programs are instructed to log output or raise error in their attack program only when the security layer gets failed. In this program we check which attack program is producing output or error. If so that means the attack is successful and that security layer is compromised.

Requirements 
===========

One must have Python installed on the system. 
Since it tests the files written in Repy V2, these addituonal files are required from Seattle Testbed organization at https://github.com/SeattleTestbed -
repy.py
encasementlib.r2py
restrictions.default
wrapper.r2py

These files must be added to the directory containing auto_grader.py

How to run 
===========

Inside the directory containing auto_grader.py, run the following command:
python auto_grader.py defense-program-folder-path attack-program-folder-path temporary-target-folder-path



