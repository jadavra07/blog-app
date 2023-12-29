package com.blog.service;

import com.blog.payload.CommentDto;

import java.util.List;

public interface CommentService  {
    public CommentDto CreatePost(long postId, CommentDto commentDto);

    void DeleteComment(long commentId);

   List<CommentDto> GetAllComment();

    List<CommentDto> GetCommentByPostId(long postId);

}
