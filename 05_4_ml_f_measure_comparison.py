
##  "all_data.csv" file is required for the operation of the program.
##  "all_data.csv" file must be located in the same directory as the program.
##The intent of this program is to find the optimal property list for Naive Bayes, and QDA and MLP algorithms.
##It follows a kind of trial-and-error method.
##The feature list obtained from the file "04_2_feature_selection_for_attack_files.py" is placed in the machine learning algorithm to start with the highest importance score.
##If the F-measure for each feature is equal to or greater than the highest value obtained, this property is added to the list. Otherwise it is removed from the list.
##As a result of the process, the program gives the highest F-measure obtained and the property list that provides it
##




#%matplotlib inline
from sklearn import metrics
from sklearn import preprocessing
from sklearn.model_selection import train_test_split
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis as QDA
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.metrics import average_precision_score
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier

from sklearn.metrics import f1_score
from sklearn.metrics import recall_score
from sklearn.metrics import precision_score




            
import pandas as pd
import warnings
warnings.filterwarnings("ignore")
import time
seconds = time.time()


#list of all columns to be imported
# the 20 features selected by the file "04_2_feature_selection_for_attack_files.py" are used here. (+ Label Feature)
features=["Bwd Packet Length Std","Flow Bytes/s","Total Length of Fwd Packets","Fwd Packet Length Std",
"Flow IAT Std","Flow IAT Min","Fwd IAT Total","Flow Duration","Bwd Packet Length Max","Flow IAT Max",
"Flow IAT Mean","Total Length of Bwd Packets","Fwd Packet Length Min","Bwd Packet Length Mean",
"Flow Packets/s","Fwd Packet Length Mean","Total Backward Packets","Total Fwd Packets","Fwd Packet Length Max",
"Bwd Packet Length Min",'Label']
    
df=pd.read_csv('all_data.csv',usecols=features)#CSV rading



print ('%-17s %-17s ' % ("Feature Number","Feature"))# print output header
for i in range(len(features)-1):
    print ('%-17s %-17s' % (i+1,features[i]))# print features  and feature numbers 


print ('\n\n\n')

attack_or_not=[]
for i in df.iloc[:,-1]:
    if i =="BENIGN":#it changes the normal label to "1" and the attack tag to "0" for use in the machine learning algorithm
        attack_or_not.append(1)
    else:
        attack_or_not.append(0)
df.iloc[:,-1]=attack_or_not
y = df.iloc[:, -1].values #labes-y
my_list=[]


least=0



ml_list={#The machine learning algorithms to be used are defined in a dictionary (ml_list).
"Naive Bayes":GaussianNB(),
"QDA":QDA(),
##"Random Forest":RandomForestClassifier(max_depth=5, n_estimators=10, max_features=1),
##"ID3" :DecisionTreeClassifier(max_depth=5,criterion="entropy"),
##"AdaBoost":AdaBoostClassifier(),
##"Nearest Neighbors":KNeighborsClassifier(3),
"MLP":MLPClassifier(hidden_layer_sizes=(13,13,13),max_iter=500)}


features.pop()#the Label tag is removed, no need any more
print ('%-17s %-30s %-10s  %-10s %-15s ' % ("ML algorithm","Feature Name","F1-score","Accuracy", "Feature List"))# print output header
for j in ml_list: # run for every machine learning.  
    my_list=[]
    for i in features: ## run for every  feature  
        my_list.append(i)
        X = df.loc[:, my_list].values # data

        ## cross-validation
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.20, random_state = 0)
       
        #machine learning algorithm is applied in this section
        clf = ml_list[j]   #                                                                       
        clf.fit(X_train, y_train)
        predict =clf.predict(X_test)
        f1=clf.score(X_test, y_test)
        result=f1_score(y_test, predict, average='macro')
        accuracy=round(clf.score(X_test, y_test),2)
        temp="["
       
        for ii in my_list: 
            temp+=str(my_list.index(ii)+1)+", " #translate property list to sequence number for less space

       
        if result>=least:# If the F-criterion is equal to or greater than the highest value previously accessed, keep the new feature. 
            least=result
            print ('%-17s %-30s %-10s  %-10s %-15s %-15s ' % (j,i,result,accuracy ,temp, "------> New feature found!!!"))

        else:#If not, remove it from the list
            my_list.remove(my_list[len(my_list)-1])
            print ('%-17s %-30s %-10s  %-10s %-15s ' % (j,i,result,accuracy ,temp))
    print("F1=" ,least,j," The most efficient feature list =",my_list,"\n\n") #print maximum F1 and the most efficient feature list




print("mission accomplished!")
print("operation time: = ",time.time()- seconds ,"secomds")
