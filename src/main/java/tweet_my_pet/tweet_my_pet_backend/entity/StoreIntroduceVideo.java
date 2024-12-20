package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "store_introduce_video")
public class StoreIntroduceVideo {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "store_introduce_video_id", nullable = false)
    private Long storeIntroduceVideoId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "store_introduce_id", nullable = false)
    private StoreIntroduce storeIntroduce;

    @Column(name = "store_introduce_video_content", nullable = false)
    private String storeIntroduceVideoContent;

}