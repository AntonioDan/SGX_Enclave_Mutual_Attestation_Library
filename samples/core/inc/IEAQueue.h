#ifndef _IEAQUEUE_H_
#define _IEAQUEUE_H_

template <class T>
class IEAQueue {
    public:
        virtual void push(T *) = 0;
        virtual T* blockingPop() = 0;
        virtual void close() = 0;
        virtual ~IEAQueue() {}
};

#endif
