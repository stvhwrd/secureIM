# Source: http://profesores.elo.utfsm.cl/~agv/elo329/Java/javamakefile.html

#------ makefile begins ------#

JFLAGS = -g     # define a variable for compiler flags (JFLAGS)
JC = javac      # define a variable for the compiler (JC)
JVM= java       # define a variable for the Java Virtual Machine (JVM)

#
# Clear any default targets for building .class files from .java files; we
# will provide our own target entry to do this in this makefile.
# make has a set of default targets for different suffixes (like .c.o)
# Currently, clearing the default for .java.class is not necessary since
# make does not have a definition for this target, but later versions of
# make may, so it doesn't hurt to make sure that we clear any default
# definitions for these
#

.SUFFIXES: .java .class


#
# Here is our target entry for creating .class files from .java files
#
.java.class:
        $(JC) $(JFLAGS) $*.java


#
# CLASSES is a macro consisting of N words (one for each java source file)
#
CLASSES = \
        Experiment.java \
        Block.java \
        Spring.java \
        PhysicsElement.java \
        Simulator.java

#
# MAIN is a variable with the name of the file containing the main method
#

MAIN = Experiment

#
# the default make target entry
# for this example it is the target classes

default: classes


# Next line is a target dependency line
# This target entry uses Suffix Replacement within a macro:
# $(macroname:string1=string2)
# In the words in the macro named 'macroname' replace 'string1' with 'string2'
# Below we are replacing the suffix .java of all words in the macro CLASSES
# with the .class suffix
#

classes: $(CLASSES:.java=.class)


# Next two lines contain a target for running the program
# Remember the tab in the second line.
# $(JMV) y $(MAIN) are replaced by their values

run: $(MAIN).class
	$(JVM) $(MAIN)

# this line is to remove all unneeded files from
# the directory when we are finished executing(saves space)
# and "cleans up" the directory of unneeded .class files
# RM is a predefined macro in make (RM = rm -f)
#

clean:
        $(RM) *.class
