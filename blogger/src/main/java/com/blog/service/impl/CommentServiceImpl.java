package com.blog.service.impl;

import com.blog.entity.Comment;
import com.blog.entity.Post;
import com.blog.exception.ResourceNotFoundException;
import com.blog.payload.CommentDto;
import com.blog.repository.CommentRepository;
import com.blog.repository.PostRepository;
import com.blog.service.CommentService;
import org.springframework.stereotype.Service;


import java.util.List;
import java.util.stream.Collectors;

@Service
public class CommentServiceImpl implements CommentService {

    private CommentRepository commentRepository;
    private PostRepository postRepository;

    public CommentServiceImpl(CommentRepository commentRepository, PostRepository postRepository) {
        this.commentRepository = commentRepository;
        this.postRepository = postRepository;
    }

    @Override
    public CommentDto CreatePost(long postId, CommentDto commentDto) {
        Post post = postRepository.findById(postId).orElseThrow(
                () -> new ResourceNotFoundException("post id is not found:" + postId)
        );
        Comment comment = new Comment();
        comment.setName(commentDto.getName());
        comment.setEmail(comment.getEmail());
        comment.setBody(commentDto.getBody());
        comment.setPost(post);

        Comment save = commentRepository.save(comment);

        CommentDto dto = new CommentDto();
        dto.setId(save.getId());
        dto.setName(save.getName());
        dto.setEmail(save.getEmail());
        dto.setBody(save.getBody());
        return dto;
    }

    @Override
    public void DeleteComment(long commentId) {
        commentRepository.findById(commentId).orElseThrow(
                ()-> new ResourceNotFoundException("Comment id is Not Found:"+commentId)
        );
            commentRepository.deleteById(commentId);
    }

    @Override
    public List<CommentDto> GetAllComment() {
        List<Comment> comments = commentRepository.findAll();
        List<CommentDto> collect = comments.stream().map(c -> mapToDto(c)).collect(Collectors.toList());
        return collect;
    }

    @Override
    public List<CommentDto> GetCommentByPostId(long postId) {
        List<Comment> comments = commentRepository.findByPostId(postId);
        List<CommentDto> collectDto = comments.stream().map(c -> mapToDto(c)).collect(Collectors.toList());
        return collectDto;
    }
    CommentDto mapToDto(Comment comment){
        CommentDto dto = new CommentDto();
        dto.setId(comment.getId());
        dto.setName(comment.getName());
        dto.setEmail(comment.getEmail());
        dto.setBody(comment.getBody());
        return dto;
    }

}
