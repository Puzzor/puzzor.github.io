---
published: false
---
## Tensorflow 基础
### Tensorflow 在Windows下的安装
	-安装Visual Studio 2015
    -安装CUDA 8.0
    -安装CUDNN 5.x并将bin include lib文件夹都拷贝到CUDA的安装目录中即可
    -安装python 3.5.x 64位
    -运行pip3 install --upgrade tensorflow-gpu
     在调用pip进行安装时如果出现Fatal error in launcher: Unable to create process using '"' 错误，则可以直接用python3 -m pip install --upgrade tensorflow-gpu 进行安装
     -如果在导入tensorflow过程中出现DLL未找到的错误则使用denpends工具打开_pywrap_tensorflow_internal.pyd查看依赖的dll并排错
     
### Tensorflow 线性回归案例学习

```python
    import tensorflow as tf
    import numpy
    import matplotlib.pyplot as plt
    rng = numpy.random
    # Parameters
    learning_rate = 0.01
    training_epochs = 2000
    display_step = 50
    # Training Data
    train_X = numpy.asarray(
        [3.3, 4.4, 5.5, 6.71, 6.93, 4.168, 9.779, 6.182, 7.59, 2.167, 7.042, 10.791, 5.313, 7.997, 5.654, 9.27, 3.1])
    train_Y = numpy.asarray(
        [1.7, 2.76, 2.09, 3.19, 1.694, 1.573, 3.366, 2.596, 2.53, 1.221, 2.827, 3.465, 1.65, 2.904, 2.42, 2.94, 1.3])
    n_samples = train_X.shape[0]
    # tf Graph Input
    X = tf.placeholder("float")
    Y = tf.placeholder("float")
    # Create Model
    # Set model weights
    W = tf.Variable(rng.randn(), name="weight")
    b = tf.Variable(rng.randn(), name="bias")
    # Construct a linear model
    activation = tf.add(tf.multiply(X, W), b)
    # Minimize the squared errors
    cost = tf.reduce_sum(tf.pow(activation - Y, 2)) / (2 * n_samples)  # L2 loss
    optimizer = tf.train.GradientDescentOptimizer(learning_rate).minimize(cost)  # Gradient descent
    # Initializing the variables
    init = tf.initialize_all_variables()

    # Launch the graph
    with tf.Session() as sess:
        sess.run(init)

        # Fit all training data
        for epoch in range(training_epochs):
            for (x, y) in zip(train_X, train_Y):
                sess.run(optimizer, feed_dict={X: x, Y: y})

            # Display logs per epoch step
            if epoch % display_step == 0:
                print("Epoch:", '%04d' % (epoch + 1), "cost=",
                      "{:.9f}".format(sess.run(cost, feed_dict={X: train_X, Y: train_Y})),
                      "W=", sess.run(W), "b=", sess.run(b))

        print("Optimization Finished!")
        print("cost=", sess.run(cost, feed_dict={X: train_X, Y: train_Y}),
              "W=", sess.run(W), "b=", sess.run(b))

        # Graphic display
        plt.plot(train_X, train_Y, 'ro', label='Original data')
        plt.plot(train_X, sess.run(W) * train_X + sess.run(b), label='Fitted line')
        plt.legend()
        plt.show()
```

### PokemonGo 中精灵进化过程中CP的线性回归预测问题
在训练小精灵过程中，一个很重要的问题是如何选取一个具有良好属性的精灵宝贝进行升级，以在升级后获得更高的CP值，我们将尝试利用线性回归模型探究升级后的CP值和哪些因素有关系。
我们首先下载训练数据[pokemon.csv](https://www.openintro.org/stat/data/pokemon.csv)
首先我们来看一元线性回归。我们拟选取1000次进行迭代，并假设升级后的CP只和初始CP有关联，利用![liner_regression.png]({{site.baseurl}}/_posts/assets/liner_regression.png)进行训练，代码如下

> 一元线性回归

	import tensorflow as tf
    import numpy
    import csv
    import matplotlib.pyplot as plt

    csv_reader = csv.reader(open('pokemon.csv'))
    old_cp = []
    new_cp = []
    for item in csv_reader:
        if csv_reader.line_num == 1:
            # 忽略第一行
            continue
        # 由于CP可能和精灵品种有关系，先只学习Pidgey品种
        if item[1] == "Pidgey":
            old_cp.append(float(item[2]))
            new_cp.append(float(item[14]))

    train_X = numpy.asarray(old_cp)
    train_Y = numpy.asarray(new_cp)
    # 学习步数
    learning_rate = 0.01
    # 迭代次数
    training_epochs = 1000
    # 显示用
    display_step = 50

    n_samples = train_X.shape[0]
    X = tf.placeholder("float")
    Y = tf.placeholder("float")
    # 随机生成W和b
    W = tf.Variable(numpy.random.randn(), name="weight")
    b = tf.Variable(numpy.random.randn(), name="bias")
    # 设置激活函数
    activation = tf.add(tf.multiply(X, W), b)
    # Loss函数
    cost = tf.reduce_sum(tf.pow(activation - Y, 2)) / (2 * n_samples)  # L2 loss
    # 利用Adam算法进行优化
    # 对于该Pokemon数据集，如果使用梯度下降算法(GradientDescentOptimizer),则会产生问题
    optimizer = tf.train.AdamOptimizer(learning_rate).minimize(cost)  # Gradient descent
    # 初始化参数
    init = tf.initialize_all_variables()

    # 运行Graph
    with tf.Session() as sess:
        sess.run(init)

        # 训练模型
        for epoch in range(training_epochs):
            for (x, y) in zip(train_X, train_Y):
                sess.run(optimizer, feed_dict={X: x, Y: y})

            # 显示
            if epoch % display_step == 0:
                print("迭代次数:", '%04d' % (epoch + 1), "损失=",
                      "{:.9f}".format(sess.run(cost, feed_dict={X: train_X, Y: train_Y})),
                      "W=", sess.run(W), "b=", sess.run(b))

        print("训练完成!")
        print("损失=", sess.run(cost, feed_dict={X: train_X, Y: train_Y}),
              "W=", sess.run(W), "b=", sess.run(b))

        plt.plot(train_X, train_Y, 'ro', label='Trainning Data')
        plt.plot(train_X, sess.run(W) * train_X + sess.run(b), label='Liner Model')
        plt.legend()
        plt.show()

训练完成后我们发现最后的损失是30.3758，W为1.88108，b为4.19906,图形如下：
![lr_result_1.png]({{site.baseurl}}/_posts/assets/lr_result_1.png)

看到上述结果，我们的问题是：这个是最好结果么？应该不是，于是我们考虑是不是可能是二元、三元等线性相关，比如和原始CP的二次方，三次方等等，于是我们分别修改模型为：

   
 
