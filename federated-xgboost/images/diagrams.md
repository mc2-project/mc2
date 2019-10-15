# Visualizing Federated XGBoost

## High Level

![federated diagram](federated-xgboost-diagram.png)

## Finding a Split

 ![diagram 1](detail_1.png)  

 ![diagram 2](detail_2.png)  

 ![diagram 3](detail_3.png)  

 ![diagram 4](detail_4.png)  

The above four steps are looped to create one decision tree. Stopping conditions include

* reaching the `max_depth` configurable parameter in the training method.  
* when no split is found to give a benefit score greater than some specified value gamma.  
* when metrics tested against a validation set are not improving once every k number of rounds, where k is configurable.
