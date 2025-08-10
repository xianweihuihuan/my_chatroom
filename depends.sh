#!/bin/bash

#传递两个参数：
# 1. 可执行程序的路径名
# 2. 目录名称 --- 将这个程序的依赖库拷贝到指定目录下
declare depends
get_depends() {
    depends=$(ldd $1 | awk '{if (match($3,"/")){print $3}}')
    mkdir $2
    cp -Lr $depends $2
}

get_depends ./client/build/client ./client/depends

cp /bin/nc ./client/

get_depends /bin/nc ./client/depends
