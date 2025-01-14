package queue

import (
	"context"
	"log"
	"sync"
)

// Queue holds name, list of jobs and context with cancel.
type Queue struct {
	name   string
	jobs   chan Job
	ctx    context.Context
	cancel context.CancelFunc
}

// Job - holds logic to perform some operations during queue execution.
type Job struct {
	Type   uint
	Len    int
	Data   []byte
	Action func(data []byte, len int) error
}

// Worker responsible for queue serving.
type Worker struct {
	Queue *Queue
}

// NewQueue instantiates new queue.
func NewQueue(name string) *Queue {
	ctx, cancel := context.WithCancel(context.Background())

	return &Queue{
		jobs:   make(chan Job),
		name:   name,
		ctx:    ctx,
		cancel: cancel,
	}
}

// AddJobs adds jobs to the queue and cancels channel.
func (q *Queue) AddJobs(jobs []Job) {
	var wg sync.WaitGroup
	wg.Add(len(jobs))

	for _, job := range jobs {
		go func(job Job) {
			q.AddJob(job)
			wg.Done()
		}(job)
	}

	go func() {
		wg.Wait()
		q.cancel()
	}()

}

// AddJob sends job to the channel.
func (q *Queue) AddJob(job Job) {
	q.jobs <- job
	//log.Printf("New job %d added to %s queue", job.Type, q.name)
}

// Run performs job execution.
func (j Job) Run() error {
	//log.Printf("Job running: %d\n", j.Type)
	err := j.Action(j.Data, j.Len)
	if err != nil {
		return err
	}

	return nil
}

// NewWorker initialises new Worker.
func NewWorker(queue *Queue) *Worker {
	return &Worker{
		Queue: queue,
	}
}

// DoWork processes jobs from the queue (jobs channel).
func (w *Worker) DoWork() bool {
	for {
		select {
		// if context was canceled.
		case <-w.Queue.ctx.Done():
			//log.Printf("Work done in queue %s: %s!", w.Queue.name, w.Queue.ctx.Err())
			return true
		// if job received.
		case job := <-w.Queue.jobs:
			err := job.Run()
			if err != nil {
				log.Print(err)
				continue
			}
		}
	}
}
