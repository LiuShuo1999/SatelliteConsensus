/*
* Filename : ipc.h
* copyright : (C) 2006 by zhonghonglie
* Function : 声明 IPC 机制的函数原型和全局变量
*/
#ifndef IPC_H
#define IPC_H
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/msg.h>
 #include <unistd.h>
#define BUFSZ 256

//建⽴或获取 ipc 的⼀组函数的原型说明
int get_ipc_id(char *proc_file,key_t key);
char *set_shm(key_t shm_key,int shm_num,int shm_flag);
int set_msq(key_t msq_key,int msq_flag);
int set_sem(key_t sem_key,int sem_val,int sem_flag);
int down(int sem_id);
int up(int sem_id);

/*信号灯控制⽤的共同体*/
typedef union semuns {
    int val;
} Sem_uns;

/* 消 息 结 构 体 */
// typedef struct msgbuf {
//     long mtype;
//     char mtext[1];
// } Msg_buf;



//consensus
//key_t mtx;
//int mtx_sem;
//key_t mtx2;
//int mtx_sem2;
//int sem_flg;
//int sem_val;

// //smoker 2
// key_t material2;
// int m2_sem;

// //smoker 3
// key_t material3;
// int m3_sem;

// //producer
// key_t _finish;
// int finish_sem;

// key_t pro_mutex;
// int promtx_sem;


// int sem_val;
// int sem_flg;
// int shm_flg;

// //⽣产消费者共享缓冲区即其有关的变量
// key_t buff_key;
// int buff_num;
// char *buff_ptr;


// int get_ipc_id(char *proc_file, key_t key) {
//     FILE *pf; int i, j;
//     char line[BUFSZ], colum[BUFSZ];
//     if ((pf = fopen(proc_file, "r")) == NULL) {
//         perror("Proc file not open");
//         exit(EXIT_FAILURE);
//     }
//     fgets(line, BUFSZ, pf);
//     while (!feof(pf)) {
//         i = j = 0;
//         fgets(line, BUFSZ, pf);
//         while (line[i] == ' ') i++;
//         while (line[i] != ' ') colum[j++] = line[i++];
//         colum[j] = '\0';
//         if (atoi(colum) != key) continue;
//         j = 0;
//         while (line[i] == ' ') i++;
//         while (line[i] != ' ') colum[j++] = line[i++];
//         colum[j] = '\0';
//         i = atoi(colum);
//         fclose(pf);
//         return i;
//     }
//     fclose(pf);
//     return -1;
// }





// /*
// * 信号灯上的down/up 操作
// * semid:信号灯数组标识符
// * semnum:信号灯数组下标
// * buf:操作信号灯的结构
// */
// int down(int sem_id) {
//     struct sembuf buf;
//     buf.sem_op = -1;
//     buf.sem_num = 0;
//     buf.sem_flg = SEM_UNDO;
//     if ((semop(sem_id, &buf, 1)) < 0) {
//         perror("down error ");
//         exit(EXIT_FAILURE);
//     }
//     return EXIT_SUCCESS;
// }
// int up(int sem_id) {
//     struct sembuf buf;
//     buf.sem_op = 1;
//     buf.sem_num = 0;
//     buf.sem_flg = SEM_UNDO;
//     if ((semop(sem_id, &buf, 1)) < 0) {
//         perror("up error ");
//         exit(EXIT_FAILURE);
//     }
//     return EXIT_SUCCESS;
// }

// /*
// * set_sem 函数建⽴⼀个具有 n 个信号灯的信号量
// * 如果建⽴成功，返回 ⼀个信号灯数组的标识符 sem_id
// * 输⼊参数：
// * sem_key 信号灯数组的键值
// * sem_val 信号灯数组中信号灯的个数
// * sem_flag 信号等数组的存取权限
// */
// int set_sem(key_t sem_key, int sem_val, int sem_flg) {
//     int sem_id;
//     Sem_uns sem_arg;
//     //测试由 sem_key 标识的信号灯数组是否已经建⽴
//     if ((sem_id = get_ipc_id("/proc/sysvipc/sem", sem_key)) < 0 ) {
//         //semget 新建⼀个信号灯,其标号返回到 sem_id
//         if ((sem_id = semget(sem_key, 1, sem_flg)) < 0) {
//             perror("semaphore create error");
//             exit(EXIT_FAILURE);
//         }
//         //设置信号灯的初值sem_arg.val = sem_val;
//         sem_arg.val = sem_val;
//         if (semctl(sem_id, 0, SETVAL, sem_arg) < 0) {
//             perror("semaphore set error");
//             exit(EXIT_FAILURE);
//         }
//     }
//     return sem_id;
// }

// /*
// * set_shm 函数建⽴⼀个具有 n 个字节 的共享内存区
// * 如果建⽴成功，返回 ⼀个指向该内存区⾸地址的指针 shm_buf
// * 输⼊参数：
// * shm_key 共享内存的键值
// * shm_val 共享内存字节的⻓度
// * shm_flag 共享内存的存取权限
// */
// char *set_shm(key_t shm_key, int shm_num, int shm_flg) {
//     int i, shm_id;
//     char *shm_buf;
//     //测试由 shm_key 标识的共享内存区是否已经建⽴
//     if ((shm_id = get_ipc_id("/proc/sysvipc/shm", shm_key)) < 0 ) {
//         //shmget 新建 ⼀个⻓度为 shm_num 字节的共享内存,其标号返回shm_id
//         if ((shm_id = shmget(shm_key, shm_num, shm_flg)) < 0) {
//             perror("shareMemory set error"); exit(EXIT_FAILURE);
//         }
//         //shmat 将由 shm_id 标识的共享内存附加给指针 shm_buf
//         if ((shm_buf = (char *)shmat(shm_id, 0, 0)) < (char *)0) {
//             perror("get shareMemory error"); exit(EXIT_FAILURE);
//         }
//         for (i = 0; i < shm_num; i++) shm_buf[i] = 0; //初始为 0
//     }
//     //shm_key 标识的共享内存区已经建⽴,将由 shm_id 标识的共享内存附加给指针 shm_buf
//     if ((shm_buf = (char *)shmat(shm_id, 0, 0)) < (char *)0) {
//         perror("get shareMemory error");
//         exit(EXIT_FAILURE);
//     }
//     return shm_buf;
// }
// /*
// * set_msq 函数建⽴⼀个消息队列
// * 如果建⽴成功，返回 ⼀个消息队列的标识符 msq_id
// * 输⼊参数：
// * msq_key 消息队列的键值
// * msq_flag 消息队列的存取权限
// */
// int set_msq(key_t msq_key, int msq_flg) {
//     int msq_id;
//     //测试由 msq_key 标识的消息队列是否已经建⽴
//     if ((msq_id = get_ipc_id("/proc/sysvipc/msg", msq_key)) < 0 ) {
//         //msgget 新建⼀个消息队列,其标号返回到 msq_id
//         if ((msq_id = msgget(msq_key, msq_flg)) < 0) {
//             perror("messageQueue set error"); exit(EXIT_FAILURE);
//         }
//     }
//     return msq_id;
// }



#endif /* ipc.h */
