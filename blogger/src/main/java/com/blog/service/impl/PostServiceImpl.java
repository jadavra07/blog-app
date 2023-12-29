package com.blog.service.impl;

import com.blog.entity.Post;
import com.blog.exception.ResourceNotFoundException;
import com.blog.payload.PostDto;
import com.blog.repository.PostRepository;
import com.blog.service.PostService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class PostServiceImpl implements PostService {

    private PostRepository postRepository;

    public PostServiceImpl(PostRepository postRepository) {
        this.postRepository = postRepository;
    }

    @Override
    public PostDto createPost(PostDto postDto) {
        Post post = new Post();
        post.setTitle(postDto.getTitle());
        post.setDescription(postDto.getDescription());
        post.setContent(postDto.getContent());

        Post savedPost = postRepository.save(post);

        PostDto dto = new PostDto();
        dto.setId(savedPost.getId());
        dto.setTitle(savedPost.getTitle());
        dto.setDescription(savedPost.getDescription());
        dto.setContent(savedPost.getContent());
        dto.setMessage("post is create !!");

        return dto;
    }

    @Override
    public void deletePost(long id) {
       Post post =  postRepository.findById(id).orElseThrow(
                 ()->new ResourceNotFoundException("Post not found with id:"+id)
         );

       postRepository.deleteById(id);

    }

    @Override
    public List<PostDto> getAllPost(int pageNO, int pageSize, String sortBy, String sortDir) {
        Sort sort = sortDir.equalsIgnoreCase(Sort.Direction.ASC.name()) ? Sort.by(sortBy).ascending()
                : Sort.by(sortBy).descending();

        Pageable pageable = PageRequest.of(pageNO, pageSize,sort);
        Page<Post> posts = postRepository.findAll(pageable);
        List<Post> postlist = posts.getContent();
        List<PostDto> collect = postlist.stream().map(p -> mapToDto(p)).collect(Collectors.toList());
        return collect;
    }
    PostDto mapToDto(Post post) {
        PostDto dto = new PostDto();
        dto.setId(post.getId());
        dto.setTitle(post.getTitle());
        dto.setContent(post.getContent());
        dto.setDescription(post.getDescription());
        return dto;
    }

    @Override
    public PostDto UpdatePost(long postId, PostDto postDto) {
       Post post = postRepository.findById(postId).orElseThrow(
                ()-> new ResourceNotFoundException("post not fount with id:"+postId)
        );
       post.setTitle(postDto.getTitle());
       post.setDescription(postDto.getDescription());
       post.setContent(postDto.getContent());

        Post saved = postRepository.save(post);
        PostDto dto = mapToDto(saved);
        return dto;
    }

}
