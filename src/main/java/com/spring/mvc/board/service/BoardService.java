package com.spring.mvc.board.service;

import com.spring.mvc.board.domain.Board;
import com.spring.mvc.board.repository.BoardMapper;
import com.spring.mvc.common.paging.Page;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class BoardService {

    private final BoardMapper boardMapper;

    //게시물 목록 가져오기
    public List<Board> getArticles(Page page) {
//        List<Board> articles = boardMapper.getArticles(page);
        List<Board> articles = boardMapper.getSearchArticles(page);

        //3분 이내 신규글 new마크 붙이기
        for (Board article : articles) {
            //각 게시물들의 등록시간 읽어오기(밀리초)
            long regTime = article.getRegDate().getTime();

            //현재시간 읽어오기(밀리초)
            long now = System.currentTimeMillis();

            if (now - regTime < 60 * 3 * 1000) {
                article.setNewFlag(true);
            }
        }

        return articles;
    }

    //총 게시물 수 조회
    public int getCount(Page page) {
        return boardMapper.getTotalCount(page);
    }

    //게시글 상세조회
    @Transactional
    public Board getContent(int boardNo) {
        Board content = boardMapper.getContent(boardNo);
        boardMapper.upViewCount(boardNo);
        return content;
    }

    //게시글 등록
    public boolean insert(Board board) {
        return boardMapper.insertArticle(board);
    }

    //게시글 삭제
    public boolean remove(int boardNo) {
        return boardMapper.deleteArticle(boardNo);
    }

    //게시물 수정
    public boolean modify(Board board) {
        return boardMapper.modifyArticle(board);
    }
}
