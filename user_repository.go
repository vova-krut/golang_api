package main

import (
	"errors"
	"sync"
)

type InMemoryUserStorage struct {
 	lock sync.RWMutex
 	storage map[string]User
}

func NewInMemoryUserStorage() *InMemoryUserStorage {
	
	return &InMemoryUserStorage {
		lock: sync.RWMutex{},
		storage: make(map[string]User),
 	}
}

func (s *InMemoryUserStorage) Add(login string, user User) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.storage[login].Email != "" {
		return errors.New("this login already exists")
	}
	s.storage[login] = user
	return nil
}

func (s *InMemoryUserStorage) Get(login string) (User, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.storage[login].Email != "" {
		return s.storage[login], nil
	}
	return User{}, errors.New("invalid login params")
}

func (s *InMemoryUserStorage) Update(login string, user User) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.storage[login].Email == "" {
		return errors.New("invalid login params")
	}
	s.storage[login] = user
	return nil
}

func (s *InMemoryUserStorage) Delete(login string) (User, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if u, exists := s.storage[login]; exists {
		delete(s.storage, login)
		return u, nil
	}
	return User{}, errors.New("this user doesn't exist")
}