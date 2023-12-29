package com.blog.service;

import com.blog.payload.CommentDto;
import com.blog.payload.PostDto;

import java.util.List;

public interface PostService {
    public PostDto createPost(PostDto postDto);

    void deletePost(long id);


    List<PostDto> getAllPost(int pageNO, int pageSize, String sortBy, String sortDir);


    PostDto UpdatePost(long postId, PostDto postDto);

}


