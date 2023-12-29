package com.blog.controller;

import com.blog.payload.CommentDto;
import com.blog.service.CommentService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/Comments")
public class CommentController {

    private CommentService commentService;

    public CommentController(CommentService commentService) {
        this.commentService = commentService;
    }

    //http://localhost:8080/api/Comments?postId=1
    @PostMapping
    public ResponseEntity<CommentDto> createComment(@RequestParam("postId") long postId, @RequestBody CommentDto commentDto) {
        CommentDto dto = commentService.CreatePost(postId, commentDto);
        return new ResponseEntity<>(dto, HttpStatus.OK);
    }

    //http://localhost:8080/api/Comments?postId=1
    @DeleteMapping("/{commentId}")
    public ResponseEntity<String> deleteComment(@PathVariable long commentId) {
        commentService.DeleteComment(commentId);
        return new ResponseEntity<>("Comment is Deleted", HttpStatus.OK);
    }

    //http://localhost:8080/api/Comments/1
    @GetMapping("/{postId}")
    public ResponseEntity<List<CommentDto>> getCommentByPostId(@PathVariable long postId) {
        List<CommentDto> dto = commentService.GetCommentByPostId(postId);
        return new ResponseEntity<>(dto,HttpStatus.OK);
    }

    //http://localhost:8080/api/Comments
    //http://localhost:8080/api/Comments?pageNo=0&pageSize=3
    @GetMapping
    public ResponseEntity<List<CommentDto>> getAllComment() {
        List<CommentDto> commentDtos = commentService.GetAllComment();
        return new ResponseEntity<>(commentDtos, HttpStatus.OK);
    }


}
