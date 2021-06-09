# Anomaly-Detection-in-Networks-Using-Machine-Learning
A thesis submitted for the degree of Master of Science in Computer Networks and Security
###### This file gives information on how to use the implementation files of "Anomaly Detection in Networks Using Machine Learning" ( A thesis submitted for the degree of Master of Science in Computer Networks and Security written by Kahraman Kostas )


Python 3.6 was used to create the application files. Before running the files, it must be ensured that [Python 3.6](https://www.python.org/downloads/) and the following libraries are installed.

| Library | Task |
| ------ | ------ |
|[ Sklearn ](http://scikit-learn.org/stable/install.html)| Machine Learning Library|
| [ Numpy ](http://www.numpy.org/) |Mathematical Operations|
| [ Pandas  ](https://pandas.pydata.org/pandas-docs/stable/install.html)|  Data Analysis Tools |
| [ Matplotlib ](https://matplotlib.org/users/installing.html) |Graphics and Visuality|


 

The implementation phase consists of 5 steps, which are:
1-	Pre-processing
2-	Statistics
3-	Attack Filtering
4-	Feature Selection
5-	Machine Learning Implementation



Each of these steps contains one or more Python files. The same file was saved with both "py" and "ipynb" extensions. The code they contain is exactly the same. The file with the ipynb extension has the advantage of saving the state of the last run of that file and the screen output.

Thus, screen output can be seen without re-running the files. Files with the ipynb extension can be run using the [jupyter notebook](http://jupyter.org/install) program. When running the codes, the sequence numbers in the filenames should be followed.

Because the output of almost every program is the prerequisite for the operation of the next program. Each step is described in detail below.


## 1 - Pre-processing
This step consists of a single file ([preprocessing.ipynb](https://github.com/bozbil/Anomaly-Detection-in-Networks-Using-Machine-Learning/blob/master/01_preprocessing.ipynb)). For this program to work, the dataset ([CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)) files must be in the "CSVs" folder in the same location as the program. The dataset files can be access  [ here ](https://drive.google.com/open?id=1-uwoKddOHgRxS8vth-nGBqBtz-qzRSAX).  (The reason that these files are given an external link is that the maximum limit of the file in the cseegit system is 10 MB)

As a result of executing this file, a file named "all_data.csv" is created. This file is a prerequisite for the other steps to work.

The most recent runtime of this file was recorded as 328 seconds. The technical specifications of the computer on which it is run are given below.



|  | |   |
| ------ |--|  ------ |
|Central Processing Unit|:|Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz 2.90 GHz|
| Random Access Memory	|:|	8 GB (7.74 GB usable)|
| Operating System	|:|	Windows 10 Pro 64-bit |
| Graphics Processing Unit	|:|	AMD Readon (TM) 530|



# 2 - Statistics
This step consists of a single file ([statistics.ipynb](https://github.com/bozbil/Anomaly-Detection-in-Networks-Using-Machine-Learning/blob/master/02_statistics.ipynb)). This program examines the file "all_data.csv" and prints the statistics of attack and benign registry on this screen. It is not a prerequisite for any file. It only gives information.

The last run time of this file was recorded as 13 seconds.


# 3 - Attack Filtering

This step consists of a single file ([attack_filter.ipynb](https://github.com/bozbil/Anomaly-Detection-in-Networks-Using-Machine-Learning/blob/master/03_attack_filter.ipynb)). This program uses the "all_data.csv" file to create attack files and then it saves them in the "./attacks/" location. The Dataset contains 12 attack types in total. Therefore, 12 CSV files are created for these attacks. Within each file are 30% attack and 70% benign registry.This step is the prerequisite for the fourth and fifth steps.
The last run time of this file was recorded as 304 seconds.


# 4 - Feature Selection

This step consists of two files.


####   a - [feature_selection_for_attack_files.ipynb](https://github.com/bozbil/Anomaly-Detection-in-Networks-Using-Machine-Learning/blob/master/04_1_feature_selection_for_attack_files.ipynb)


This program uses attack files located under the "attacks" folder. The aim of this program is to determine which features are important for each attack. For this purpose, It is used the Random Forest Regressor algorithm to calculate the importance weights of the features in the dataset.
These acquired features are used in machine learning section As a screen output, it sorts its features and weights from large to small and shows them on the bar chart (average 20 attributes per attack type).

The most recent run of this file was recorded as 4817 seconds.


####  b - [feature_selection_for_all_data.ipynb](https://github.com/bozbil/Anomaly-Detection-in-Networks-Using-Machine-Learning/blob/master/04_2_feature_selection_for_all_data.ipynb)


This program applies the previous step to the entire data set. Thus, it creates the feature importance weights of that is valid for the entire dataset. It uses the "all_data.csv" file and the Random Forest Regressor algorithm. As a screen output, it sorts its features and weights from large to small and shows them on the bar chart (20 attributes in total for all attacks).

The last run time of this file was recorded as 25929 seconds.



# 5 -  Machine Learning Implementation
This step applies the machine learning algorithms to the data set and consists of 5 files.



####  a - [machine_learning_implementation_for_attack_files.ipynb](https://github.com/bozbil/Anomaly-Detection-in-Networks-Using-Machine-Learning/blob/master/05_1_machine_learning_implementation_for_attack_files%20.ipynb)



this program uses the attack files under the "./attacks/" folder as a dataset. The features used are the 4 features with the highest weight for each file, produced by the feature_selection_for_attack_files file.  This file applies 7 machine learning algorithms to each file 10 times and prints the results of these operations on the screen and in the file "./attacks/results_1.csv". It also creates box and whisker graphics of the results and prints them both on the screen and in the "./attacks/result_graph_1/" folder.

The last run time of this file was recorded as 3601 seconds.


####  b - [machine_learning_implementation_with_18_feature.ipynb](https://github.com/bozbil/Anomaly-Detection-in-Networks-Using-Machine-Learning/blob/master/05_2_machine_learning_implementation_with_18_feature.ipynb)



This program implements machine learning methods in the file "all_data.csv". Uses the features used in the previous step. The set of features to be used consists of combining the 4 features with the highest importance-weight achieved for each attack in "machine_learning_implementation_for_attack_files"  step under a single roof. Thus, 4 features are obtained from each of the 12 attack types, resulting in a pool of features consisting of 48 attributes. After the repetitions are removed, the number of features is 18. 

This file applies 7 machine learning algorithms to "all_data.csv" file 10 times and prints the results of these operations on the screen and in the file "./attacks/results_2.csv". It also creates box and whisker graphics of the results and prints them both on the screen and in the "./attacks/result_graph_2/" folder.

The last run time of this file was recorded as 25082 seconds.



####  c -  [machine_learning_implementation_with_7_feature.ipynb](https://github.com/bozbil/Anomaly-Detection-in-Networks-Using-Machine-Learning/blob/master/05_3_machine_learning_implementation_with_7_feature.ipynb)



This program implements machine learning methods in the file "all_data.csv". The features used are the 7 features with the highest weight, produced by the feature_selection_for_all_data file. 
This file applies 7 machine learning algorithms to "all_data.csv" file 10 times and prints the results of these operations on the screen and in the file "./attacks/results_3.csv". It also creates box and whisker graphics of the results and prints them both on the screen and in the "./attacks/result_graph_3/" folder.

The last run time of this file was recorded as 12714 seconds.



####  d -  [ml_f_measure_comparison.ipynb](https://github.com/bozbil/Anomaly-Detection-in-Networks-Using-Machine-Learning/blob/master/05_4_ml_f_measure_comparison.ipynb)




This program runs with the file "all_data.csv". It finds feature giving the highest f-measure for Naive Bayes, QDA, and MLP algorithms, and prints them on the screen.

The last run time of this file was recorded as 2092 seconds.


####  e-  [machine_learning_implementation_final.ipynb](https://github.com/bozbil/Anomaly-Detection-in-Networks-Using-Machine-Learning/blob/master/05_4_ml_f_measure_comparison.ipynb)


This program uses "all_data.csv" file as dataset. In feature selection, it follows a different path. To improve performance for the Naive Bayes, QDA and MLP algorithms, it uses the features generated by the ml_F-criterion_comparison file. In the other four algorithms, it uses 7 features with the highest significance, generated by the feature_selection_for_all_data file.

This file applies 7 machine learning algorithms to "all_data.csv" file 10 times and prints the results of these operations on the screen and in the file "./attacks/results_final.csv". It also creates box and whisker graphics of the results and prints them both on the screen and in the "./attacks/result_graph_final/" folder.

The last run time of this file was recorded as 18561 seconds.


## Citations
If you use the source code please cite the following paper:

```
@MastersThesis{kostas2018,
    author = {Kostas,Kahraman},
    title = {{Anomaly Detection in Networks Using Machine Learning}},
    institution = {Computer Science and Electronic Engineering - CSEE},
    school = {University of Essex},
    address= {Colchester, UK},
    year={2018}
    }
```




##  [you can reach the thesis via this link](https://github.com/bozbil/Anomaly-Detection-in-Networks-Using-Machine-Learning/blob/master/Anomaly_Detection_in_Networks_Using_Machine_Learning.pdf)


