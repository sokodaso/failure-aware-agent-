# Failure Aware Coding Agent Skills

## Purpose
The Failure Aware Coding Agent extends a coding agent with failure-oriented reasoning 

The agent should use:
1. Repository/code context 
2. Historical failure knowledge 
3. software oriented FMEA reasoning 
4. software oriented FTA reasoning 

to identify and learn from software failures during coding tasks.


## Core Workflow 
For each coding task:
1. Understand the user's requested behaviour 
2. Inspect the relevant repository files and dependencies 
3. Analyze the code for potential failure points 
4. Query the failure knowledge database for relevant historical failures 
5. Perform FMEA when bottom up analysis is appropriate 
6. Perform FTA when a top K Failure Event needs casual decomposition 
7. Perform task (modify or generate) code when a failure is confirmed or sufficiently supported
8. Record the useful failure knowledge


##  FMEA Skill
Use FMEA for bottom up analysis 

For each relevant function or component identify:
- Function 
- Failure Mode 
- Effect 

## FTA Skill
Use FTA for top down analysis for analyzing how combinations of lower level events can produce an undesirable software or system behavior

FMEA asks , "What could go wrong with this function/component?"

FTA asks , "How could this undesirable behavior occur?"

## TOP EVENT 
The undesirable event that needs to be analyzed.

# LOGIC GATES 
AND 
The parent requires ALL child nodes to be true for the parent to be true.

OR 
The parent requires AT LEAST ONE child node to be true for the parent to be true.

## Rules
Use the following evidence hierarchy:
1. Current repository code
2. Explicit task criteria or requirement
3. Retrieved historical failure evidence
4. FMEA and FTA skills 

Never present an inference as an observed fact 

## Failure Aware Coding Workflow

Task -> Repository Understanding -> Historical Failure Knowledge -> FMEA/FTA Analysis -> Code Modification/Generation -> Knowledge Recording