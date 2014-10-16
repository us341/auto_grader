''' Description:
    This program determines if a student attack code is able to bypass a given defensive
    security layer.   An attack is considered to be successful if it prints to stdout or stderr.

    The process is repeated for multiple students on multiple defense layers (Reference monitors)
    If a student had multiple attack files, they were successful if *any*
    attack succeeds.

    *** Note: This assumes that the attacks were pre-vetted.
        All attack codes are in the same directory. Reference monitors are in a separate directory.


    The output of this will be a list of lines that say the defense name,
    the attacking student name, and a list of tests that bypass the security
    layer.   If a student is not successful, nothing is output.

'''



import os
import glob
import subprocess
import shutil
import csv
import time
import signal # using SIGKILL

# Paths to reference monitor folders
# path_RM_RW='/Users/Sara/RM/Richard-MZ'
#path_RM_Ian='/Users/Sara/RM/Ref_Monitor_Ian'
#path_Att_Ian='/Users/Sara/RM/Attacks_Ian'

path_DefenseFolder = '/Users/Sara/RM/JC_Fall_2012_PrivateWrite/Ref_Monitor_JC_PW'
path_AttackFolder = '/Users/Sara/RM/JC_Fall_2012_PrivateWrite/Attacks_JC_PW'

#path_AttackFolder = '/Users/Sara/RM/JC_Fall_2012_PrivateWrite/t1'

# Paths  to temp folder where the attack is run
path_TempFolder = '/Users/Sara/RM//Temp_Folder'

#part of filename to look for
attack_ext = "*.repy"       #justin's student files
def_ext = "reference*"      #justin's student files
#def_ext="*monitor*"
#attack_ext="*attack*"



def get_student_ID(attack_fnlist):
  ''' Given a list of the total attack files, get a list of all of the
    student IDs.   This assumes that the file names are in the format:
    studentname_testinfo...
  '''

  studentset = set()
  for attackfn in attack_fnlist:
    # I assume everything before the first _ is the student ID.   I will
    # raise an exception for a file like  foo.repy...

    if len(attackfn.split('_')) == 0:
       raise ValueError('File name "'+attackfn+'" should contain an underscore!')

    studentname = attackfn.split('_')[0]
    studentset.add(studentname)

  return sorted(list(studentset))


def get_student_attack_code(studentname, attack_fnlist):
  ''' This will return only the attack code from a specific student.'''

  thisstudentattacks = []
  for thisattack in attack_fnlist:
    # need the underscore to stop bob from matching bobby's tests.
    if thisattack.startswith(studentname+'_'):
      thisstudentattacks.append(thisattack)


  return thisstudentattacks


def check_if_student_attacks_succeed(student_attackfn, defensefn):
  ''' Returns a list of any code for a student that produce stderr or stdout.
  An empty list is returned if none were successful
  otherwise'''

  successfulattacks = []

  for attackfn in student_attackfn:
    if did_this_attack_succeed(attackfn, defensefn):
      successfulattacks.append(attackfn)

  return successfulattacks




def did_this_attack_succeed(attackFilename, defenseFilename):
    ''' Returns True if the attack produces stderr or stdout,
    False otherwise
    '''

    timeout=30

    os.mkdir(path_TempFolder)  # make a temp folder
    os.chdir(path_TempFolder)  # cd to temp folder at this point


    shutil.copy('/Users/Sara/RM/Repy/encasementlib.r2py', path_TempFolder + '/encasementlib.r2py')
    shutil.copy('/Users/Sara/RM/Repy/wrapper.r2py', path_TempFolder + '/wrapper.r2py')

    shutil.copy(path_DefenseFolder  + '/' + defenseFilename, path_TempFolder + '/' + defenseFilename)
    shutil.copy(path_AttackFolder + '/' + attackFilename, path_TempFolder + '/' + attackFilename)

    start = time.time()

    pobj = subprocess.Popen(
        ['python', '../Repy/repy.py', '--stop=Repy_stop_this', '../Repy/restrictions.default', 'encasementlib.r2py', defenseFilename,
         attackFilename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # NOT A BUG: Note that this will not get all of the stdout or stderr because we are polling for completion.
    # Substantial output may cause the program to block, which is a very bad thing... in most cases.
    # Since output / errput is failure and timeout is failure, we're actually okay with it here.
    while pobj.poll() is None:
        time.sleep(0.1)
        now = time.time()
        if now - start > timeout:
            # Signal for the repyVM to stop (due to the --stop option)
            file("Repy_stop_this","w").close()
            # wait for it to stop...
            pobj.wait()
            stdout = "timeout"
            stderr = "timeout"
            break
    else:
        (stdout, stderr) = pobj.communicate()


    os.chdir(path_AttackFolder)  # go back to attack folder
    shutil.rmtree(path_TempFolder)  #remove the temp directory


    if stdout != '' or stderr !='':  # or time out
        return True

    else:
        return False



def row_builder(success_list,original_list,defenseFilename):

     num_success=len(success_list)

     matrix_row=[0]*(len(original_list))
     matrix_row[0]=defenseFilename

     for element in range(num_success):

         for row_num in range(len(original_list)):
            if original_list[row_num]==success_list[element]:
                matrix_row[row_num]=1    # if an attack is successful, put a 1 in the matrix

     return matrix_row






def main():

    # If the temp folder is left over from last time, remove it.
    if os.path.exists(path_TempFolder):
        shutil.rmtree(path_TempFolder)

    os.chdir(path_DefenseFolder)  # cd to defense monitor folder
    defense_fnlist =glob.glob(def_ext)

    os.chdir(path_AttackFolder)    # cd to attack folder
    attack_fnlist=glob.glob(attack_ext)

    studentIDlist = get_student_ID(attack_fnlist)
    print 'number of students in the course', len(studentIDlist)

    header_attackmatrix=attack_fnlist
    header_attackmatrix.insert(0,'All attack files-->')

    header_studentmatrix=studentIDlist
    header_studentmatrix.insert(0,'All students -->')

    resultFile1 = open("All_Attacks_matrix.csv",'wb')
    wr_allattacks = csv.writer(resultFile1)
    wr_allattacks.writerow(header_attackmatrix)

    resultFile2 = open("All_Students_matrix.csv",'wb')
    wr_students = csv.writer(resultFile2)
    wr_students.writerow(header_studentmatrix)


    for defenseFilename in defense_fnlist:

        collection_successful_attacks=list()
        collection_successful_students=list()

        print 'This is defense file --->', defenseFilename

        for attackingstudent in studentIDlist:

            # get just this student's attacks
            student_attackfns = get_student_attack_code(attackingstudent,attack_fnlist)
           # print len(student_attackfns)

          #  attacks_perstudent = open("attack.csv",'wb')
          #  wr = csv.writer(attacks_perstudent)
          #  wr.writerow([len(student_attackfns),student_attackfns])

            successfulattacks = check_if_student_attacks_succeed(student_attackfns,defenseFilename)


            if successfulattacks!=[]:

                print defenseFilename,'---attacked by--- ', attackingstudent,'----->', successfulattacks



                collection_successful_attacks=collection_successful_attacks+successfulattacks
                collection_successful_students.append(attackingstudent)

        #print 'successful attacks',collection_successful_attacks
        row_all_attacks=row_builder(collection_successful_attacks,attack_fnlist,defenseFilename)
        row_students=row_builder(collection_successful_students,studentIDlist,defenseFilename)

        wr_allattacks.writerow(row_all_attacks)
        wr_students.writerow(row_students)

        print 'row completed with students',row_students

     #attacksperstudent = open("attack.csv",'wb')
     #   wr = csv.writer(attacksperstudent)

    #  wr.writerow([len(student_attackfns)])



if __name__ == "__main__":
    main()





