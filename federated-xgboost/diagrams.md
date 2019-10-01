# Visualizing Federated XGBoost

## High Level

![federated diagram](./images/federated-xgboost-diagram.png)

## Finding a Split

 ![diagram 1](./images/detail_1.png)

 ![diagram 2](./images/detail_2.png)

 ![diagram 3](./images/detail_3.png)

 ![diagram 4](./images/detail_4.png)

The above four steps are looped to create one decision tree. Stopping conditions include

* reaching the `max_depth` configurable parameter in the training method.  
* when no split is found to give a benefit score greater than some specified value gamma.  
* when metrics tested against a validation set are not improving once every k number of rounds, where k is configurable.
