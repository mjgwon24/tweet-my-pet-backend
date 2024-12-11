package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "store_review_picture")
public class StoreReviewPicture {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "store_review_picture_id", nullable = false)
    private Long storeReviewPiectureId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "store_review_id", nullable = false)
    private StoreReview storeReview;

    @Column(name = "store_review_picture_content", nullable = false)
    private String storeReviewPictureContent;

}