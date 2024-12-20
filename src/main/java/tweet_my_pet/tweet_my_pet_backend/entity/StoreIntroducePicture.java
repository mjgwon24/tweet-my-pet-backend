package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "store_introduce_picture")
public class StoreIntroducePicture {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "store_introduce_picture_id", nullable = false)
    private Long storeIntroducePictureId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "store_introduce_id", nullable = false)
    private StoreIntroduce storeIntroduce;

    @Column(name = "store_introduce_picture_content", nullable = false)
    private String storeIntroducePictureContent;

}