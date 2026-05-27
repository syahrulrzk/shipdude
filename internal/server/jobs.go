package server

import (
	"sync"
)

// Job represents a background execution job (e.g., provisioning, deployment, rollback).
type Job struct {
	ID        string
	Mu        sync.Mutex
	Logs      []string
	Listeners map[string]chan string
	Done      bool
}

// NewJob initializes a new Job.
func NewJob(id string) *Job {
	return &Job{
		ID:        id,
		Listeners: make(map[string]chan string),
	}
}

// AddLog appends a line to the job's log history and broadcasts it to all listeners.
func (j *Job) AddLog(line string) {
	j.Mu.Lock()
	j.Logs = append(j.Logs, line)
	// Create a copy of the listeners slice to invoke outside the lock
	listeners := make([]chan string, 0, len(j.Listeners))
	for _, ch := range j.Listeners {
		listeners = append(listeners, ch)
	}
	j.Mu.Unlock()

	for _, ch := range listeners {
		select {
		case ch <- line:
		default:
			// Non-blocking send in case a receiver is blocked
		}
	}
}

// GetLogs returns a snapshot of the current logs.
func (j *Job) GetLogs() []string {
	j.Mu.Lock()
	defer j.Mu.Unlock()
	
	logs := make([]string, len(j.Logs))
	copy(logs, j.Logs)
	return logs
}

// RegisterListener registers a new receiver for log lines.
func (j *Job) RegisterListener(id string) chan string {
	j.Mu.Lock()
	defer j.Mu.Unlock()

	ch := make(chan string, 200)
	j.Listeners[id] = ch
	return ch
}

// UnregisterListener removes a listener by ID.
func (j *Job) UnregisterListener(id string) {
	j.Mu.Lock()
	defer j.Mu.Unlock()

	if ch, ok := j.Listeners[id]; ok {
		close(ch)
		delete(j.Listeners, id)
	}
}

// JobManager coordinates active background execution jobs.
type JobManager struct {
	Mu   sync.Mutex
	Jobs map[string]*Job
}

// NewJobManager initializes a JobManager.
func NewJobManager() *JobManager {
	return &JobManager{
		Jobs: make(map[string]*Job),
	}
}

// GetOrCreateJob retrieves or registers a job.
func (jm *JobManager) GetOrCreateJob(id string) *Job {
	jm.Mu.Lock()
	jm.Mu.Unlock() // we can do double locking or simple lock
	
	jm.Mu.Lock()
	defer jm.Mu.Unlock()

	if j, ok := jm.Jobs[id]; ok {
		return j
	}
	j := NewJob(id)
	jm.Jobs[id] = j
	return j
}

// GetJob returns a job if it exists.
func (jm *JobManager) GetJob(id string) *Job {
	jm.Mu.Lock()
	defer jm.Mu.Unlock()
	return jm.Jobs[id]
}
